//! Miscellaneous utils.

use exonum::{blockchain::BlockProof, crypto::PublicKey, helpers::ValidatorId, messages::Message};

use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub validators: Vec<PublicKey>,
}

#[derive(Debug, Fail)]
pub enum VerifyError {
    #[fail(display = "invalid validator id encountered")]
    InvalidValidatorId,
    #[fail(display = "duplicate `Precommit`s authored by the same validator")]
    DuplicateValidators,
    #[fail(display = "no sufficient validator quorum")]
    NoQuorum,
    #[fail(display = "invalid validator signature")]
    InvalidSignature,
}

impl TrustAnchor {
    pub fn verify_block_proof(&self, block_proof: &BlockProof) -> Result<(), VerifyError> {
        let validators: Result<Vec<_>, _> = block_proof
            .precommits
            .iter()
            .map(|precommit| precommit.validator())
            .map(|ValidatorId(id)| {
                self.validators
                    .get(id as usize)
                    .ok_or(VerifyError::InvalidValidatorId)
            }).collect();
        let validators = validators?;

        if validators.iter().collect::<HashSet<_>>().len() != validators.len() {
            return Err(VerifyError::DuplicateValidators);
        }
        if validators.len() < 2 * self.validators.len() / 3 + 1 {
            return Err(VerifyError::NoQuorum);
        }

        let all_signatures_are_valid = block_proof
            .precommits
            .iter()
            .zip(validators)
            .all(|(precommit, pk)| precommit.verify_signature(pk));
        if !all_signatures_are_valid {
            return Err(VerifyError::InvalidSignature);
        }
        Ok(())
    }
}
