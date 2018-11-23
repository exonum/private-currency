// Copyright 2018 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
