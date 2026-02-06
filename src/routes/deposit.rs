use axum::{Json, http::StatusCode};
use solana_sdk::{
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};
use spl_token_2022::{
    id as token_2022_program_id,
    instruction::deposit,
};
use std::str::FromStr;

use crate::{
    models::*,
    solana::create_rpc_client,
};

/// Deposit tokens from public balance to confidential pending balance
/// 
/// This converts tokens from visible public balance to encrypted confidential pending balance.
/// After depositing, you must call apply_pending_balance to make the funds available for use.
/// 
/// Flow:
/// 1. User has tokens in public balance
/// 2. Call deposit() → moves to confidential pending balance (encrypted)
/// 3. Call apply_pending_balance() → moves to confidential available balance
/// 4. Now can use for confidential transfers
pub async fn deposit_tokens(
    Json(payload): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, StatusCode> {
    tracing::info!(
        "Depositing {} tokens for wallet: {}",
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

    // 3. Load payer keypair (in production, user signs this)
    let payer = load_payer_keypair().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 4. Create deposit instruction
    // This moves tokens from public balance → confidential pending balance
    let deposit_ix = deposit(
        &token_2022_program_id(),
        &token_account,
        &token_account,  // Mint (derived from token account in real impl)
        payload.amount,
        payload.decimals,
        &wallet_pubkey,
        &[],  // Additional signers
    )
    .map_err(|e| {
        tracing::error!("Failed to create deposit instruction: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 5. Build and send transaction
    let mut transaction = Transaction::new_with_payer(
        &[deposit_ix],
        Some(&payer.pubkey()),
    );

    let recent_blockhash = client
        .get_latest_blockhash()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    transaction.sign(&[&payer], recent_blockhash);

    let signature = client
        .send_and_confirm_transaction(&transaction)
        .await
        .map_err(|e| {
            tracing::error!("Deposit transaction failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Deposit successful: {}", signature);

    Ok(Json(DepositResponse {
        success: true,
        signature: signature.to_string(),
        error: None,
    }))
}

/// Apply pending balance to make funds available for confidential operations
/// 
/// After depositing, funds sit in "pending" state. This instruction moves them
/// to "available" state where they can be used for confidential transfers.
/// 
/// This requires decrypting the pending balance using ElGamal/AES keys.
pub async fn apply_pending_balance(
    Json(payload): Json<ApplyPendingRequest>,
) -> Result<Json<ApplyPendingResponse>, StatusCode> {
    tracing::info!(
        "Applying pending balance for wallet: {}",
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

    // 4. Get account state to read pending balance
    let account_data = client
        .get_account(&token_account)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    // 5. Parse the ConfidentialTransferAccount extension
    use spl_token_2022::extension::{BaseStateWithExtensions, confidential_transfer::ConfidentialTransferAccount};
    
    let token_account_data = spl_token_2022::state::Account::unpack(&account_data.data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let extension = token_account_data
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 6. Generate ElGamal and AES keys (deterministically)
    // In production, user would provide these or we'd derive from their signature
    use crate::crypto::{generate_elgamal_keypair, generate_aes_key};
    
    // For demo: simulate user wallet
    let user_wallet = Keypair::new();
    let elgamal_keypair = generate_elgamal_keypair(&user_wallet, &token_account)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let aes_key = generate_aes_key(&user_wallet, &token_account)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 7. Create apply pending balance instruction
    use spl_token_2022::instruction::apply_pending_balance;
    
    let apply_ix = apply_pending_balance(
        &token_2022_program_id(),
        &token_account,
        None,  // Expected pending balance count (None = don't check)
        elgamal_keypair.secret(),
        &aes_key,
        &wallet_pubkey,
        &[],
    )
    .map_err(|e| {
        tracing::error!("Failed to create apply pending balance instruction: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 8. Build and send transaction
    let mut transaction = Transaction::new_with_payer(
        &[apply_ix],
        Some(&payer.pubkey()),
    );

    let recent_blockhash = client
        .get_latest_blockhash()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    transaction.sign(&[&payer], recent_blockhash);

    let signature = client
        .send_and_confirm_transaction(&transaction)
        .await
        .map_err(|e| {
            tracing::error!("Apply pending balance transaction failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Apply pending balance successful: {}", signature);

    Ok(Json(ApplyPendingResponse {
        success: true,
        signature: signature.to_string(),
        error: None,
    }))
}

// Helper function to load payer keypair
fn load_payer_keypair() -> anyhow::Result<Keypair> {
    // In production, load from secure storage or environment
    // For demo, generate a new one (in real usage, this would be funded)
    Ok(Keypair::new())
}