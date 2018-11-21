//! Cryptographic primitives used in the service.
//!
//! # Commitments and range proofs
//!
//! See [`Commitment`] and [`SimpleRangeProof`] docs for details on cryptographic commitments.
//! Commitments are used in the service instead of plaintext account balances and transfer amounts.
//! Proofs are present in [`Transfer`] transactions, allowing to assert that the transferred amount
//! is positive (i.e., the sender cannot create tokens for herself out of thin air
//! by "transferring" negative amount to somebody), and that the sender has enough tokens to
//! perform the transfer.
//!
//! # Public-key encryption
//!
//! [`enc`](::crypto::enc) module re-exports necessary primitives to [encrypt data](::EncryptedData)
//! within `Transfer`s.
//!
//! [`Commitment`]: ::crypto::Commitment
//! [`SimpleRangeProof`]: ::crypto::SimpleRangeProof
//! [`Transfer`]: ::transactions::Transfer

pub mod enc;
mod proofs;
mod serialization;

pub use self::proofs::{Commitment, Opening, SimpleRangeProof};
