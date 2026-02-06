use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;

// Request/Response models

#[derive(Debug, Deserialize)]
pub struct CreateAccountRequest {
    pub wallet_address: String,
    pub mint_address: String,
}

#[derive(Debug, Serialize)]
pub struct CreateAccountResponse {
    pub success: bool,
    pub token_account: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DepositRequest {
    pub wallet_address: String,
    pub token_account: String,
    pub amount: u64,
    pub decimals: u8,
}

#[derive(Debug, Serialize)]
pub struct DepositResponse {
    pub success: bool,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApplyPendingRequest {
    pub wallet_address: String,
    pub token_account: String,
}

#[derive(Debug, Serialize)]
pub struct ApplyPendingResponse {
    pub success: bool,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TransferRequest {
    pub sender_wallet: String,
    pub sender_token_account: String,
    pub recipient_token_account: String,
    pub recipient_elgamal_pubkey: String,
    pub amount: u64,
}

#[derive(Debug, Serialize)]
pub struct TransferResponse {
    pub success: bool,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WithdrawRequest {
    pub wallet_address: String,
    pub token_account: String,
    pub amount: u64,
    pub decimals: u8,
}

#[derive(Debug, Serialize)]
pub struct WithdrawResponse {
    pub success: bool,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GenerateProofRequest {
    pub wallet_address: String,
    pub token_account: String,
    pub threshold: u64,
}

#[derive(Debug, Serialize)]
pub struct GenerateProofResponse {
    pub success: bool,
    pub proof: String,
    pub public_inputs: Vec<String>,
    pub eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GetBalanceRequest {
    pub wallet_address: String,
    pub token_account: String,
}

#[derive(Debug, Serialize)]
pub struct GetBalanceResponse {
    pub success: bool,
    pub available_balance: u64,
    pub pending_balance: u64,
    pub decrypted_available: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}