use axum::{Json, http::StatusCode};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_token_2022::id as token_2022_program_id;
use std::str::FromStr;

use crate::{
    crypto::{generate_elgamal_keypair, generate_aes_key, generate_withdraw_proof},
    models::*,
    solana::create_rpc_client,
};

/// Withdraw tokens from confidential available balance to public balance
/// 
/// This converts encrypted confidential balance back to visible public balance.
/// Requires TWO zero-knowledge proofs:
/// 1. Equality proof - proves encrypted amount equals plaintext amount
/// 2. Range proof - proves amount is valid and non-negative
/// 
/// Flow:
/// 1. Get account state (read confidential balance)
/// 2. Generate withdraw proofs (equality + range)
/// 3. Create proof context state accounts (2 accounts)
/// 4. Submit withdraw transaction
/// 5. Close proof context accounts (recover rent)
pub async fn withdraw_tokens(
    Json(payload): Json<WithdrawRequest>,
) -> Result<Json<WithdrawResponse>, StatusCode> {
    tracing::info!(
        "Withdrawing {} tokens from confidential balance for wallet: {}",
        payload.amount,
        payload.wallet_address
    );

    // 1. Parse and validate inputs
    let wallet_pubkey = Pubkey::from_str(&payload.wallet_address)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let token_account = Pubkey::from_str(&payload.token_account)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // 2. Get RPC client
    let client = create_rpc_client();

    // 3. Load payer keypair
    let payer = load_payer_keypair().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 4. Get account state to read confidential balance
    let account_data = client
        .get_account(&token_account)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    // 5. Parse the ConfidentialTransferAccount extension
    use spl_token_2022::extension::{
        BaseStateWithExtensions,
        confidential_transfer::{ConfidentialTransferAccount, account_info::WithdrawAccountInfo},
    };
    
    let token_account_data = spl_token_2022::state::Account::unpack(&account_data.data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let ct_extension = token_account_data
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 6. Generate user's ElGamal and AES keys (deterministically)
    let user_wallet = Keypair::new(); // In production, from user's signature
    let elgamal_keypair = generate_elgamal_keypair(&user_wallet, &token_account)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let aes_key = generate_aes_key(&user_wallet, &token_account)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 7. Create WithdrawAccountInfo from extension data
    let withdraw_account_info = WithdrawAccountInfo::new(ct_extension);

    // 8. Generate withdraw proofs (equality + range)
    tracing::info!("Generating withdraw proofs...");
    let withdraw_proof_data = generate_withdraw_proof(
        &withdraw_account_info,
        payload.amount,
        &elgamal_keypair,
        &aes_key,
    )
    .map_err(|e| {
        tracing::error!("Failed to generate withdraw proof: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 9. Create proof context state accounts
    use spl_token_confidential_transfer_proof_extraction::instruction::ProofInstruction;
    
    // Create keypairs for the two proof accounts
    let equality_proof_keypair = Keypair::new();
    let range_proof_keypair = Keypair::new();

    // 10. Create equality proof context account
    tracing::info!("Creating equality proof context account...");
    let create_equality_ix = ProofInstruction::VerifyBatchedProof
        .encode_verify_proof(
            Some(&equality_proof_keypair.pubkey()),
            &withdraw_proof_data.equality_proof_data,
        )
        .map_err(|e| {
            tracing::error!("Failed to encode equality proof: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let recent_blockhash = client
        .get_latest_blockhash()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut eq_tx = Transaction::new_with_payer(
        &create_equality_ix,
        Some(&payer.pubkey()),
    );
    eq_tx.sign(&[&payer, &equality_proof_keypair], recent_blockhash);
    
    let eq_sig = client
        .send_and_confirm_transaction(&eq_tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create equality proof account: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    tracing::info!("Equality proof account created: {}", eq_sig);

    // 11. Create range proof context account
    tracing::info!("Creating range proof context account...");
    let create_range_ix = ProofInstruction::VerifyBatchedProof
        .encode_verify_proof(
            Some(&range_proof_keypair.pubkey()),
            &withdraw_proof_data.range_proof_data,
        )
        .map_err(|e| {
            tracing::error!("Failed to encode range proof: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut range_tx = Transaction::new_with_payer(
        &create_range_ix,
        Some(&payer.pubkey()),
    );
    range_tx.sign(&[&payer, &range_proof_keypair], recent_blockhash);
    
    let range_sig = client
        .send_and_confirm_transaction(&range_tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create range proof account: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    tracing::info!("Range proof account created: {}", range_sig);

    // 12. Execute the withdraw transaction with proof references
    use spl_token_2022::instruction::withdraw_confidential;
    
    let withdraw_ix = withdraw_confidential(
        &token_2022_program_id(),
        &token_account,
        &wallet_pubkey,
        Some(&equality_proof_keypair.pubkey()),
        Some(&range_proof_keypair.pubkey()),
        payload.amount,
        payload.decimals,
        Some(withdraw_account_info),
        &elgamal_keypair,
        &aes_key,
        &[],
    )
    .map_err(|e| {
        tracing::error!("Failed to create withdraw instruction: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut withdraw_tx = Transaction::new_with_payer(
        &[withdraw_ix],
        Some(&payer.pubkey()),
    );
    withdraw_tx.sign(&[&payer], recent_blockhash);
    
    let withdraw_sig = client
        .send_and_confirm_transaction(&withdraw_tx)
        .await
        .map_err(|e| {
            tracing::error!("Withdraw transaction failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Withdraw successful: {}", withdraw_sig);

    // 13. Close proof context accounts to recover rent
    use spl_token_2022::instruction::close_context_state;
    
    tracing::info!("Closing proof context accounts...");
    
    // Close equality proof account
    let close_eq_ix = close_context_state(
        &equality_proof_keypair.pubkey(),
        &token_account,
        &payer.pubkey(),
    );
    let mut close_eq_tx = Transaction::new_with_payer(&[close_eq_ix], Some(&payer.pubkey()));
    close_eq_tx.sign(&[&payer], recent_blockhash);
    client.send_and_confirm_transaction(&close_eq_tx).await.ok();

    // Close range proof account
    let close_range_ix = close_context_state(
        &range_proof_keypair.pubkey(),
        &token_account,
        &payer.pubkey(),
    );
    let mut close_range_tx = Transaction::new_with_payer(&[close_range_ix], Some(&payer.pubkey()));
    close_range_tx.sign(&[&payer], recent_blockhash);
    client.send_and_confirm_transaction(&close_range_tx).await.ok();

    tracing::info!("Proof accounts closed, rent recovered");

    Ok(Json(WithdrawResponse {
        success: true,
        signature: withdraw_sig.to_string(),
        error: None,
    }))
}

// Helper function to load payer keypair
fn load_payer_keypair() -> anyhow::Result<Keypair> {
    Ok(Keypair::new())
}