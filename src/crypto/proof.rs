use anyhow::Result;
use solana_sdk::pubkey::Pubkey;
use spl_token_2022::solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalKeypair, ElGamalPubkey},
};
use spl_token_confidential_transfer_proof_generation::{
    transfer::TransferProofData,
    withdraw::WithdrawProofData,
};
use spl_token_2022::extension::confidential_transfer::{
    account_info::{TransferAccountInfo, WithdrawAccountInfo},
    instruction::PubkeyValidityProofData,
};

/// Generate PubkeyValidityProofData for account configuration
/// This proves that an ElGamal public key is valid without revealing the secret key
pub fn generate_pubkey_validity_proof(
    elgamal_keypair: &ElGamalKeypair,
) -> Result<PubkeyValidityProofData> {
    let proof_data = PubkeyValidityProofData::new(elgamal_keypair)
        .map_err(|_| anyhow::anyhow!("Failed to generate pubkey validity proof"))?;

    Ok(proof_data)
}

/// Generate transfer proof data
/// This creates the ZK proofs needed for confidential transfers:
/// - Equality proof (proves encrypted amounts match)
/// - Ciphertext validity proof (proves encryption is correct)
/// - Range proof (proves amounts are in valid range and non-negative)
pub fn generate_transfer_proof(
    transfer_account_info: &TransferAccountInfo,
    amount: u64,
    sender_elgamal_keypair: &ElGamalKeypair,
    sender_aes_key: &AeKey,
    recipient_elgamal_pubkey: &ElGamalPubkey,
    auditor_elgamal_pubkey: Option<&ElGamalPubkey>,
) -> Result<TransferProofData> {
    let proof_data = transfer_account_info
        .generate_split_transfer_proof_data(
            amount,
            sender_elgamal_keypair,
            sender_aes_key,
            recipient_elgamal_pubkey,
            auditor_elgamal_pubkey,
        )
        .map_err(|e| anyhow::anyhow!("Failed to generate transfer proof: {:?}", e))?;

    Ok(proof_data)
}

/// Generate withdraw proof data
/// This creates the ZK proofs needed for withdrawing confidential balance to public:
/// - Equality proof (proves encrypted amount equals plaintext)
/// - Range proof (proves amount is valid and non-negative)
pub fn generate_withdraw_proof(
    withdraw_account_info: &WithdrawAccountInfo,
    amount: u64,
    elgamal_keypair: &ElGamalKeypair,
    aes_key: &AeKey,
) -> Result<WithdrawProofData> {
    let proof_data = withdraw_account_info
        .generate_proof_data(amount, elgamal_keypair, aes_key)
        .map_err(|e| anyhow::anyhow!("Failed to generate withdraw proof: {:?}", e))?;

    Ok(proof_data)
}

/// Generate a simple eligibility proof (for frontend)
/// This is a simplified proof showing the user has >= threshold tokens
/// In production, you might want a more sophisticated proof structure
pub fn generate_eligibility_proof(
    available_balance: u64,
    threshold: u64,
) -> Result<(bool, String)> {
    let eligible = available_balance >= threshold;
    
    // Generate a simple hash-based proof
    // In production, use proper ZK proof construction
    let proof = if eligible {
        format!(
            "proof:eligible:{}:{}:{}",
            available_balance,
            threshold,
            chrono::Utc::now().timestamp()
        )
    } else {
        "proof:ineligible".to_string()
    };

    Ok((eligible, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Keypair;

    #[test]
    fn test_pubkey_validity_proof() {
        let keypair = Keypair::new();
        let token_account = Pubkey::new_unique();
        let elgamal = ElGamalKeypair::new_from_signer(&keypair, &token_account.to_bytes()).unwrap();

        let proof_result = generate_pubkey_validity_proof(&elgamal);
        assert!(proof_result.is_ok());
    }

    #[test]
    fn test_eligibility_proof() {
        let (eligible, proof) = generate_eligibility_proof(100, 50).unwrap();
        assert!(eligible);
        assert!(proof.contains("eligible"));

        let (not_eligible, proof2) = generate_eligibility_proof(30, 50).unwrap();
        assert!(!not_eligible);
        assert!(proof2.contains("ineligible"));
    }
}