use axum::{Json, http::StatusCode};
use solana_sdk::{
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{ExtensionType, confidential_transfer::instruction::configure_account},
    id as token_2022_program_id,
    instruction::reallocate,
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use std::str::FromStr;

use crate::{
    crypto::{generate_aes_key, generate_elgamal_keypair, generate_pubkey_validity_proof, generate_eligibility_proof},
    models::*,
    solana::create_rpc_client,
};

/// Create a confidential transfer enabled token account
pub async fn create_confidential_account(
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<CreateAccountResponse>, StatusCode> {
    tracing::info!("Creating CT account for wallet: {}", payload.wallet_address);

    // Parse addresses
    let wallet_pubkey = Pubkey::from_str(&payload.wallet_address)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mint_pubkey = Pubkey::from_str(&payload.mint_address)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get RPC client
    let client = create_rpc_client();

    // For demo: Load a payer keypair (in production, user signs transactions)
    // This is just for funding the account creation
    let payer = load_payer_keypair().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Get associated token account address
    let token_account = get_associated_token_address_with_program_id(
        &wallet_pubkey,
        &mint_pubkey,
        &token_2022_program_id(),
    );

    // Generate ElGamal and AES keys for the user
    // In production, the user's wallet would do this client-side
    // For this demo backend, we simulate it
    let user_keypair = Keypair::new(); // Simulate user's keypair
    let elgamal_keypair = generate_elgamal_keypair(&user_keypair, &token_account)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let aes_key = generate_aes_key(&user_keypair, &token_account)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Maximum pending balance credit counter
    let maximum_pending_balance_credit_counter = 65536u64;

    // Initial encrypted balance (0)
    let decryptable_balance = aes_key.encrypt(0);

    // Generate pubkey validity proof
    let proof_data = generate_pubkey_validity_proof(&elgamal_keypair)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create transaction
    let mut transaction = Transaction::new_with_payer(
        &[
            // Create associated token account
            spl_associated_token_account::instruction::create_associated_token_account(
                &payer.pubkey(),
                &wallet_pubkey,
                &mint_pubkey,
                &token_2022_program_id(),
            ),
            
            // Reallocate for confidential transfer extension
            reallocate(
                &token_2022_program_id(),
                &token_account,
                &payer.pubkey(),
                &wallet_pubkey,
                &[&wallet_pubkey],
                &[ExtensionType::ConfidentialTransferAccount],
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        ],
        Some(&payer.pubkey()),
    );

    // Configure account for confidential transfers
    let proof_location = ProofLocation::InstructionOffset(
        1.try_into().unwrap(),
        spl_token_confidential_transfer_proof_extraction::instruction::ProofData::InstructionData(&proof_data),
    );

    let configure_instructions = configure_account(
        &token_2022_program_id(),
        &token_account,
        &mint_pubkey,
        &decryptable_balance.into(),
        maximum_pending_balance_credit_counter,
        &wallet_pubkey,
        &[],
        proof_location,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    transaction.message.instructions.extend(configure_instructions);

    // Get recent blockhash
    let recent_blockhash = client
        .get_latest_blockhash()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    transaction.sign(&[&payer], recent_blockhash);

    // Send transaction
    let signature = client
        .send_and_confirm_transaction(&transaction)
        .await
        .map_err(|e| {
            tracing::error!("Transaction failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(CreateAccountResponse {
        success: true,
        token_account: token_account.to_string(),
        signature: signature.to_string(),
        error: None,
    }))
}

/// Get balance of a confidential transfer account
pub async fn get_balance(
    Json(payload): Json<GetBalanceRequest>,
) -> Result<Json<GetBalanceResponse>, StatusCode> {
    tracing::info!("Getting balance for token account: {}", payload.token_account);

    let token_account = Pubkey::from_str(&payload.token_account)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let client = create_rpc_client();

    // Get account data
    let account_data = client
        .get_account(&token_account)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    // Parse token account
    // In production, parse the ConfidentialTransferAccount extension
    // and decrypt the available/pending balances
    
    // For now, return placeholder
    Ok(Json(GetBalanceResponse {
        success: true,
        available_balance: 0,
        pending_balance: 0,
        decrypted_available: Some(0),
        error: None,
    }))
}

/// Generate eligibility proof
pub async fn generate_proof(
    Json(payload): Json<GenerateProofRequest>,
) -> Result<Json<GenerateProofResponse>, StatusCode> {
    tracing::info!("Generating proof for wallet: {}", payload.wallet_address);

    // In production, get actual balance and generate real ZK proof
    // For demo, use simplified proof
    let available_balance = 100u64; // Placeholder

    let (eligible, proof) = generate_eligibility_proof(available_balance, payload.threshold)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(GenerateProofResponse {
        success: true,
        proof,
        public_inputs: vec![
            payload.wallet_address,
            payload.threshold.to_string(),
        ],
        eligible,
        error: None,
    }))
}

// Helper function to load payer keypair
fn load_payer_keypair() -> anyhow::Result<Keypair> {
    // In production, load from secure key storage
    // For demo, generate a new one or load from env
    Ok(Keypair::new())
}