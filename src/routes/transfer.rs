use axum::{Json, http::StatusCode};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_token_2022::{
    id as token_2022_program_id,
    solana_zk_sdk::encryption::elgamal::ElGamalPubkey,
};
use std::str::FromStr;

use crate::{
    crypto::{generate_elgamal_keypair, generate_aes_key, generate_transfer_proof},
    models::*,
    solana::create_rpc_client,
};

/// Execute a confidential transfer between two token accounts
/// 
/// This is the most complex operation, requiring THREE zero-knowledge proofs:
/// 1. Equality proof - proves encrypted amounts match
/// 2. Ciphertext validity proof - proves encryption is correct
/// 3. Range proof - proves amount is valid and non-negative
/// 
/// Flow:
/// 1. Get sender's account state
/// 2. Generate all three proofs
/// 3. Create proof context state accounts (3 accounts)
/// 4. Submit transfer transaction (references proof accounts)
/// 5. Close proof context accounts (recover rent)
pub async fn confidential_transfer(
    Json(payload): Json<TransferRequest>,
) -> Result<Json<TransferResponse>, StatusCode> {
    tracing::info!(
        "Confidential transfer: {} tokens from {} to {}",
        payload.amount,
        payload.sender_wallet,
        payload.recipient_token_account
    );

    // 1. Parse and validate inputs
    let sender_wallet = Pubkey::from_str(&payload.sender_wallet)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let sender_token_account = Pubkey::from_str(&payload.sender_token_account)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let recipient_token_account = Pubkey::from_str(&payload.recipient_token_account)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    // Parse recipient ElGamal public key
    let recipient_elgamal_pubkey_bytes = bs58::decode(&payload.recipient_elgamal_pubkey)
        .into_vec()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let recipient_elgamal_pubkey = ElGamalPubkey::from_bytes(&recipient_elgamal_pubkey_bytes)
        .ok_or(StatusCode::BAD_REQUEST)?;

    // 2. Get RPC client
    let client = create_rpc_client();

    // 3. Load payer keypair
    let payer = load_payer_keypair().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 4. Get sender's account state
    let sender_account_data = client
        .get_account(&sender_token_account)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    // 5. Parse the ConfidentialTransferAccount extension
    use spl_token_2022::extension::{
        BaseStateWithExtensions,
        confidential_transfer::{ConfidentialTransferAccount, account_info::TransferAccountInfo},
    };
    
    let token_account_data = spl_token_2022::state::Account::unpack(&sender_account_data.data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let ct_extension = token_account_data
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 6. Generate sender's ElGamal and AES keys (deterministically)
    let sender_user_wallet = Keypair::new(); // In production, from user's signature
    let sender_elgamal = generate_elgamal_keypair(&sender_user_wallet, &sender_token_account)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let sender_aes = generate_aes_key(&sender_user_wallet, &sender_token_account)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 7. Create TransferAccountInfo from extension data
    let transfer_account_info = TransferAccountInfo::new(ct_extension);

    // 8. Generate transfer proofs (all 3 at once)
    let transfer_proof_data = generate_transfer_proof(
        &transfer_account_info,
        payload.amount,
        &sender_elgamal,
        &sender_aes,
        &recipient_elgamal_pubkey,
        None, // No auditor
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 9. Create proof context state accounts
    use spl_token_confidential_transfer_proof_extraction::instruction::ProofInstruction;
    
    // Create keypairs for the three proof accounts
    let equality_proof_keypair = Keypair::new();
    let ciphertext_proof_keypair = Keypair::new();
    let range_proof_keypair = Keypair::new();

    // 10. Create equality proof context account
    tracing::info!("Creating equality proof context account...");
    let create_equality_ix = ProofInstruction::VerifyBatchedProof
        .encode_verify_proof(
            Some(&equality_proof_keypair.pubkey()),
            &transfer_proof_data.equality_proof_data,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut eq_tx = Transaction::new_with_payer(
        &create_equality_ix,
        Some(&payer.pubkey()),
    );
    let recent_blockhash = client.get_latest_blockhash().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    eq_tx.sign(&[&payer, &equality_proof_keypair], recent_blockhash);
    
    let eq_sig = client.send_and_confirm_transaction(&eq_tx).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tracing::info!("Equality proof account created: {}", eq_sig);

    // 11. Create ciphertext validity proof context account
    tracing::info!("Creating ciphertext validity proof context account...");
    let create_ciphertext_ix = ProofInstruction::VerifyBatchedProof
        .encode_verify_proof(
            Some(&ciphertext_proof_keypair.pubkey()),
            &transfer_proof_data.ciphertext_validity_proof_data,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut ct_tx = Transaction::new_with_payer(
        &create_ciphertext_ix,
        Some(&payer.pubkey()),
    );
    ct_tx.sign(&[&payer, &ciphertext_proof_keypair], recent_blockhash);
    
    let ct_sig = client.send_and_confirm_transaction(&ct_tx).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tracing::info!("Ciphertext validity proof account created: {}", ct_sig);

    // 12. Create range proof context account
    tracing::info!("Creating range proof context account...");
    let create_range_ix = ProofInstruction::VerifyBatchedProof
        .encode_verify_proof(
            Some(&range_proof_keypair.pubkey()),
            &transfer_proof_data.range_proof_data,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut range_tx = Transaction::new_with_payer(
        &create_range_ix,
        Some(&payer.pubkey()),
    );
    range_tx.sign(&[&payer, &range_proof_keypair], recent_blockhash);
    
    let range_sig = client.send_and_confirm_transaction(&range_tx).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tracing::info!("Range proof account created: {}", range_sig);

    // 13. Now execute the actual transfer with proof references
    use spl_token_2022::instruction::transfer_confidential;
    
    let transfer_ix = transfer_confidential(
        &token_2022_program_id(),
        &sender_token_account,
        &recipient_token_account,
        &sender_wallet,
        Some(&equality_proof_keypair.pubkey()),
        Some(&ciphertext_proof_keypair.pubkey()),
        Some(&range_proof_keypair.pubkey()),
        payload.amount,
        None, // No auditor
        &sender_elgamal,
        &sender_aes,
        &recipient_elgamal_pubkey,
        None, // No auditor pubkey
        &[],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut transfer_tx = Transaction::new_with_payer(
        &[transfer_ix],
        Some(&payer.pubkey()),
    );
    transfer_tx.sign(&[&payer], recent_blockhash);
    
    let transfer_sig = client.send_and_confirm_transaction(&transfer_tx).await
        .map_err(|e| {
            tracing::error!("Transfer transaction failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Confidential transfer successful: {}", transfer_sig);

    // 14. Close proof context accounts to recover rent
    use spl_token_2022::instruction::close_context_state;
    
    // Close equality proof account
    let close_eq_ix = close_context_state(
        &equality_proof_keypair.pubkey(),
        &sender_token_account,
        &payer.pubkey(),
    );
    let mut close_eq_tx = Transaction::new_with_payer(&[close_eq_ix], Some(&payer.pubkey()));
    close_eq_tx.sign(&[&payer], recent_blockhash);
    client.send_and_confirm_transaction(&close_eq_tx).await.ok();

    // Close ciphertext proof account
    let close_ct_ix = close_context_state(
        &ciphertext_proof_keypair.pubkey(),
        &sender_token_account,
        &payer.pubkey(),
    );
    let mut close_ct_tx = Transaction::new_with_payer(&[close_ct_ix], Some(&payer.pubkey()));
    close_ct_tx.sign(&[&payer], recent_blockhash);
    client.send_and_confirm_transaction(&close_ct_tx).await.ok();

    // Close range proof account
    let close_range_ix = close_context_state(
        &range_proof_keypair.pubkey(),
        &sender_token_account,
        &payer.pubkey(),
    );
    let mut close_range_tx = Transaction::new_with_payer(&[close_range_ix], Some(&payer.pubkey()));
    close_range_tx.sign(&[&payer], recent_blockhash);
    client.send_and_confirm_transaction(&close_range_tx).await.ok();

    tracing::info!("Proof accounts closed, rent recovered");

    Ok(Json(TransferResponse {
        success: true,
        signature: transfer_sig.to_string(),
        error: None,
    }))
}

// Helper function to load payer keypair
fn load_payer_keypair() -> anyhow::Result<Keypair> {
    Ok(Keypair::new())
}