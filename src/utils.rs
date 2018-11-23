//! Miscellaneous utils.

use exonum::{blockchain::BlockProof, crypto::PublicKey, helpers::ValidatorId, messages::Message};

use std::collections::HashSet;

/// Trust anchor for block verification.
// This implementation is simplified; it assumes *a priori* knowledge of the current list
// of validators. For maximum security, the trust anchor should be the hash of the genesis block;
// the current list of validators could be derived from it using information about configuration
// changes and, possibly, anchoring info.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    validators: Vec<PublicKey>,
}

/// Error occuring during block header verification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Fail)]
pub enum BlockVerifyError {
    /// Invalid validator ID encountered in `BlockProof`.
    #[fail(display = "invalid validator id encountered")]
    InvalidValidatorId,

    /// Duplicate `Precommit`s authored by the same validator.
    #[fail(display = "duplicate `Precommit`s authored by the same validator")]
    DuplicateValidators,

    /// No sufficient validator quorum.
    #[fail(display = "no sufficient validator quorum")]
    NoQuorum,

    /// Invalid validator signature.
    #[fail(display = "invalid validator signature")]
    InvalidSignature,
}

impl TrustAnchor {
    /// Creates a trust anchor based on provided consensus keys of all validators
    /// in the blockchain network.
    pub fn new<I>(consensus_keys: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        TrustAnchor {
            validators: consensus_keys.into_iter().collect(),
        }
    }

    /// Verifies a `BlockProof` w.r.t. this trust anchor.
    pub fn verify_block_proof(&self, block_proof: &BlockProof) -> Result<(), BlockVerifyError> {
        let validators: Result<Vec<_>, _> = block_proof
            .precommits
            .iter()
            .map(|precommit| precommit.validator())
            .map(|ValidatorId(id)| {
                self.validators
                    .get(id as usize)
                    .ok_or(BlockVerifyError::InvalidValidatorId)
            }).collect();
        let validators = validators?;

        if validators.iter().collect::<HashSet<_>>().len() != validators.len() {
            return Err(BlockVerifyError::DuplicateValidators);
        }
        if validators.len() < 2 * self.validators.len() / 3 + 1 {
            return Err(BlockVerifyError::NoQuorum);
        }

        let all_signatures_are_valid = block_proof
            .precommits
            .iter()
            .zip(validators)
            .all(|(precommit, pk)| precommit.verify_signature(pk));
        if !all_signatures_are_valid {
            return Err(BlockVerifyError::InvalidSignature);
        }
        Ok(())
    }
}
