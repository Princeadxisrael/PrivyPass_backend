use anyhow::Result;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use spl_token_2022::solana_zk_sdk::encryption::{
    auth_encryption::AeKey, elgamal::ElGamalKeypair,
};

/// Generate ElGamal keypair from wallet signer and token account address
/// This ensures deterministic key generation per user per token account
pub fn generate_elgamal_keypair(
    wallet_keypair: &Keypair,
    token_account: &Pubkey,
) -> Result<ElGamalKeypair> {
    let elgamal_keypair = ElGamalKeypair::new_from_signer(
        wallet_keypair,
        &token_account.to_bytes(),
    )
    .map_err(|_| anyhow::anyhow!("Failed to generate ElGamal keypair"))?;

    Ok(elgamal_keypair)
}

/// Generate AES key from wallet signer and token account address
/// Used for encrypting/decrypting confidential balances
pub fn generate_aes_key(
    wallet_keypair: &Keypair,
    token_account: &Pubkey,
) -> Result<AeKey> {
    let aes_key = AeKey::new_from_signer(
        wallet_keypair,
        &token_account.to_bytes(),
    )
    .map_err(|_| anyhow::anyhow!("Failed to generate AES key"))?;

    Ok(aes_key)
}

/// Decrypt a confidential balance using the AES key
pub fn decrypt_balance(
    aes_key: &AeKey,
    encrypted_balance: &[u8; 36], // AeCiphertext size
) -> Result<u64> {
    // Note: This is a simplified version
    // In production, we'd use the full AeCiphertext struct
    // and proper decryption methods
    
    // For now, we'll just return a placeholder
    // Real implementation would use aes_key to decrypt
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Keypair;

    #[test]
    fn test_key_generation() {
        let wallet = Keypair::new();
        let token_account = Pubkey::new_unique();

        let elgamal_result = generate_elgamal_keypair(&wallet, &token_account);
        assert!(elgamal_result.is_ok());

        let aes_result = generate_aes_key(&wallet, &token_account);
        assert!(aes_result.is_ok());
    }

    #[test]
    fn test_deterministic_keys() {
        let wallet = Keypair::new();
        let token_account = Pubkey::new_unique();

        let elgamal1 = generate_elgamal_keypair(&wallet, &token_account).unwrap();
        let elgamal2 = generate_elgamal_keypair(&wallet, &token_account).unwrap();

        // Keys should be deterministic (same input = same output)
        assert_eq!(
            elgamal1.pubkey().to_bytes(),
            elgamal2.pubkey().to_bytes()
        );
    }
}