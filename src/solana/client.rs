use anyhow::Result;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    signature::Keypair,
    transaction::Transaction,
};
use std::sync::Arc;

/// Create a Solana RPC client
pub fn create_rpc_client() -> Arc<RpcClient> {
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

    Arc::new(RpcClient::new_with_commitment(
        rpc_url,
        CommitmentConfig::confirmed(),
    ))
}

/// Send and confirm a transaction
pub async fn send_and_confirm(
    client: &RpcClient,
    transaction: &Transaction,
    signers: &[&Keypair],
) -> Result<String> {
    let signature = client
        .send_and_confirm_transaction_with_spinner(transaction)
        .await?;

    Ok(signature.to_string())
}

/// Get account info
pub async fn get_account_info(
    client: &RpcClient,
    pubkey: &solana_sdk::pubkey::Pubkey,
) -> Result<Option<solana_sdk::account::Account>> {
    let account = client.get_account(pubkey).await.ok();
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rpc_client() {
        let client = create_rpc_client();
        assert!(Arc::strong_count(&client) > 0);
    }
}