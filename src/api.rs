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

//! HTTP API for the service.

use exonum::{
    api::{self, ServiceApiState},
    blockchain::{Block, BlockProof, Blockchain, Schema as CoreSchema, Transaction},
    crypto::{CryptoHash, Hash, PublicKey},
    storage::{
        proof_list_index::ListProofError,
        proof_map_index::{MapProofError, ProofMapKey},
        ListProof, MapProof, Snapshot, StorageValue,
    },
};

use std::{collections::HashSet, fmt};

use super::SERVICE_ID;
use storage::{maybe_create_wallet, maybe_transfer, Event, EventTag, Schema, Wallet};
use transactions::{CreateWallet, CryptoTransactions, Transfer};

pub use utils::{BlockVerifyError, TrustAnchor};

/// HTTP API for the private cryptocurrency service.
#[derive(Debug)]
pub enum Api {}

/// Query for the `wallet` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletQuery {
    /// Public key of the account to check.
    pub key: PublicKey,
    /// The starting index for the user's list of events.
    pub start_history_at: u64,
}

/// Event changing balance of a wallet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename = "kebab-case")]
pub enum FullEvent {
    /// Event corresponding to wallet creation. There is only one such event in wallet history -
    /// the very first one.
    CreateWallet(CreateWallet),

    /// Transfer to or from the wallet.
    ///
    /// Note that outgoing transfers are recorded in the sender's history immediately after
    /// the commitment. The incoming transfers, on the other hand, need to be [`Accept`]ed.
    ///
    /// [`Accept`]: ::transactions::Accept
    Transfer(Transfer),

    /// Rolled-back transfer returning the funds to the sender.
    Rollback(Transfer),
}

impl FullEvent {
    /// Converts `Event` into its full form by loading the transaction data
    /// from the provided snapshot.
    fn from<T: AsRef<dyn Snapshot>>(event: &Event, snapshot: T) -> Self {
        let id = event.transaction_hash();
        match event.tag() {
            tag if tag == EventTag::CreateWallet as u8 => {
                FullEvent::CreateWallet(maybe_create_wallet(snapshot, id).expect("CreateWallet"))
            }
            tag if tag == EventTag::Transfer as u8 => {
                FullEvent::Transfer(maybe_transfer(snapshot, id).expect("Transfer"))
            }
            tag if tag == EventTag::Rollback as u8 => {
                FullEvent::Rollback(maybe_transfer(snapshot, id).expect("Transfer"))
            }
            _ => unreachable!(),
        }
    }

    fn tag(&self) -> EventTag {
        match self {
            FullEvent::CreateWallet(..) => EventTag::CreateWallet,
            FullEvent::Transfer(..) => EventTag::Transfer,
            FullEvent::Rollback(..) => EventTag::Rollback,
        }
    }

    /// Does this event correspond to a given storage-form event?
    fn corresponds_to(&self, event: &Event) -> bool {
        if self.tag() as u8 != event.tag() {
            return false;
        }

        let hash = match self {
            FullEvent::CreateWallet(tx) => tx.hash(),
            FullEvent::Transfer(tx) => tx.hash(),
            FullEvent::Rollback(tx) => tx.hash(),
        };
        hash == *event.transaction_hash()
    }
}

/// Cryptographically authenticated proof of the state for a single wallet.
///
/// The proof contains several parts:
///
/// - Block header together with authorizing `Precommit`s
/// - Proof connecting the block header with the wallets table in the storage,
///   and then with a particular wallet.
/// - Information about new events in the wallet history and unaccepted incoming transfers,
///   if any.
///
/// # Proof of absence
///
/// The proof can also be used to prove the absence of a wallet. In this case, the last part
/// of the proof (history and unaccepted transfers) is empty.
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletProof {
    block_proof: BlockProof,
    wallet_table_proof: MapProof<Hash, Hash>,
    wallet_proof: MapProof<PublicKey, Wallet>,
    #[serde(flatten)]
    wallet_contents: Option<WalletContentsProof>,
}

/// Information about wallet state useful for a client, obtained after checking a `WalletProof`.
#[derive(Debug)]
pub struct CheckedWalletProof {
    /// Block information.
    pub block: Block,

    /// General information about the wallet.
    pub wallet: Option<Wallet>,

    /// New events concerning the wallet. The event with index `0` corresponds to an event
    /// at index `query.start_history_at` in the wallet history, and so on.
    ///
    /// If [`wallet`](#structfield.wallet) is `None`, the `history` is empty.
    pub history: Vec<FullEvent>,

    /// Unaccepted incoming transfers for the wallet.
    ///
    /// If [`wallet`](#structfield.wallet) is `None`, the `unaccepted_transfers` vector is empty.
    pub unaccepted_transfers: Vec<Transfer>,
}

/// Part of a `WalletProof` related to auxiliary tables (wallet history and unaccepted transfers).
// This struct is inlined into the parent, so it's not public.
#[derive(Debug, Serialize, Deserialize)]
struct WalletContentsProof {
    history: Vec<FullEvent>,
    unaccepted_transfers: Vec<Transfer>,
    history_proof: Option<ListProof<Event>>,
    unaccepted_transfers_proof: MapProof<Hash, ()>,
}

/// Error during `WalletProof` verification.
#[derive(Debug, Fail)]
pub enum VerifyError {
    /// Error verifying block header.
    #[fail(display = "block verification failed: {}", _0)]
    Block(#[fail(cause)] BlockVerifyError),

    /// Error verifying one of `MapProof`s included into the wallet proof.
    #[fail(
        display = "verifying `MapProof` for {} failed: {}",
        proof_description, error
    )]
    MapProof {
        /// Cause of the verification failure.
        #[fail(cause)]
        error: MapProofError,
        /// Description of the proof where an error has occurred.
        proof_description: ProofDescription,
    },

    /// Error verifying one of `ListProof`s included into the wallet proof.
    #[fail(
        display = "verifying `ListProof` for {} failed: {:?}",
        proof_description, error
    )]
    ListProof {
        /// Cause of the verification failure.
        error: ListProofError,
        /// Description of the proof where an error has occurred.
        proof_description: ProofDescription,
    },

    /// A `ListProof` or `MapProof` is disconnected from its parent. In other words, the root hash
    /// of the index restored from the proof does not match one obtained from other proof data.
    #[fail(display = "Merkle proof for {} is disconnected from parent", _0)]
    ProofDisconnect(ProofDescription),

    /// A `ListProof` or `MapProof` does not prove presence or absence of a key,
    /// which it is expected to prove.
    #[fail(display = "Merkle proof for {} misses expected key", _0)]
    MissingKey(ProofDescription),

    /// A Merkle proof proves existence of keys that do not match the plain data included into
    /// to the proof.
    ///
    /// For example, this error could occur if the proof mentions 3 new events in wallet history,
    /// but the corresponding `ListProof` includes only 2 of these events.
    #[fail(display = "Merkle proof and entries for {} do not match", _0)]
    KeyMismatch(ProofDescription),

    /// The proof shows existence of the requested wallet, but the events and unaccepted transfers
    /// are missing from the proof.
    #[fail(display = "missing wallet contents")]
    NoContents,
}

/// Description of a part of a `WalletProof`.
///
/// Used in [`VerifyError`](VerifyError).
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum ProofDescription {
    /// `MapProof` from the `state_hash` mentioned in the block header, to the wallets table.
    WalletsTable,
    /// `MapProof` from the wallets table to a specific wallet.
    Wallet,
    /// `ListProof` for wallet history.
    History,
    /// `MapProof` for unaccepted transfers.
    UnacceptedTransfers,
}

impl fmt::Display for ProofDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ProofDescription::*;

        match self {
            WalletsTable => f.write_str("wallets table"),
            Wallet => f.write_str("wallet"),
            History => f.write_str("history"),
            UnacceptedTransfers => f.write_str("unaccepted transfers"),
        }
    }
}

impl From<BlockVerifyError> for VerifyError {
    fn from(e: BlockVerifyError) -> Self {
        VerifyError::Block(e)
    }
}

impl WalletProof {
    /// Creates a new proof based on a given storage snapshot.
    fn new<T: AsRef<dyn Snapshot>>(snapshot: T, query: &WalletQuery) -> Self {
        let core_schema = CoreSchema::new(&snapshot);
        let block_proof = core_schema
            .block_and_precommits(core_schema.height())
            .expect("BlockProof");
        let wallet_table_proof = core_schema.get_proof_to_service_table(SERVICE_ID, 0);

        let schema = Schema::new(&snapshot);
        let wallets = schema.wallets();

        WalletProof {
            block_proof,
            wallet_table_proof,
            wallet_proof: wallets.get_proof(query.key),
            wallet_contents: if wallets.contains(&query.key) {
                Some(WalletContentsProof::new(&snapshot, query))
            } else {
                None
            },
        }
    }

    /// Checks if a `MapProof` contains a specified key.
    ///
    /// # Return value
    ///
    /// - If the proof is correct and contains the key, the method returns `Ok(Some(_))`.
    /// - If the proof (correctly) proves absence of the key, the method returns `Ok(None)`.
    /// - Otherwise, we return an `Err(_)`.
    fn check_map_proof_with_single_key<K, V>(
        proof: MapProof<K, V>,
        expected_hash: Hash,
        key: &K,
        proof_description: ProofDescription,
    ) -> Result<Option<V>, VerifyError>
    where
        K: ProofMapKey + Eq,
        V: StorageValue + Clone,
    {
        let checked = proof.check().map_err(|error| VerifyError::MapProof {
            error,
            proof_description,
        })?;
        if checked.merkle_root() != expected_hash {
            return Err(VerifyError::ProofDisconnect(proof_description));
        }
        let (_, value) = checked
            .all_entries()
            .into_iter()
            .find(|&(k, _)| k == key)
            .ok_or_else(|| VerifyError::MissingKey(proof_description))?;
        Ok(value.cloned())
    }

    /// Checks the proof, returning information contained in the proof that might be
    /// interesting to client applications.
    pub fn check(
        &self,
        trust_anchor: &TrustAnchor,
        query: &WalletQuery,
    ) -> Result<CheckedWalletProof, VerifyError> {
        // First, verify the block proof.
        trust_anchor.verify_block_proof(&self.block_proof)?;

        // Verify proof for wallets table.
        let wallets_hash: Option<Hash> = Self::check_map_proof_with_single_key(
            self.wallet_table_proof.clone(),
            *self.block_proof.block.state_hash(),
            &Blockchain::service_table_unique_key(SERVICE_ID, 0),
            ProofDescription::WalletsTable,
        )?;
        // The key corresponding to the wallets table cannot be missing.
        let wallets_hash =
            wallets_hash.ok_or(VerifyError::MissingKey(ProofDescription::WalletsTable))?;

        // Verify proof for the wallet.
        let wallet: Option<Wallet> = Self::check_map_proof_with_single_key(
            self.wallet_proof.clone(),
            wallets_hash,
            &query.key,
            ProofDescription::Wallet,
        )?;

        if let Some(ref wallet) = wallet {
            if let Some(ref wallet_contents) = self.wallet_contents {
                let (history, unaccepted_transfers) = wallet_contents.check(wallet, query)?;
                Ok(CheckedWalletProof {
                    block: self.block_proof.block.clone(),
                    wallet: Some(wallet.clone()),
                    history,
                    unaccepted_transfers,
                })
            } else {
                return Err(VerifyError::NoContents);
            }
        } else {
            // No wallet.
            Ok(CheckedWalletProof {
                block: self.block_proof.block.clone(),
                wallet: None,
                history: vec![],
                unaccepted_transfers: vec![],
            })
        }
    }
}

impl WalletContentsProof {
    /// Creates a new proof based on a given storage snapshot.
    fn new<T: AsRef<dyn Snapshot>>(snapshot: T, query: &WalletQuery) -> Self {
        let schema = Schema::new(&snapshot);

        // Get wallet history.
        let history_index = schema.history_index(&query.key);
        let start_history_at = query.start_history_at;
        let history: Vec<_> = history_index
            .iter_from(start_history_at)
            .map(|event| FullEvent::from(&event, &snapshot))
            .collect();
        // ...and the corresponding proof.
        let history_proof = if history.is_empty() {
            None
        } else {
            Some(history_index.get_range_proof(start_history_at, history_index.len()))
        };

        // Get hashes of unaccepted transfers.
        let unaccepted_transfers: Vec<_> = schema
            .unaccepted_transfers(&query.key)
            .into_iter()
            .collect();
        // ...and the corresponding proof.
        let unaccepted_transfers_proof = schema
            .unaccepted_transfers_index(&query.key)
            .get_multiproof(unaccepted_transfers.iter().cloned());
        let unaccepted_transfers: Vec<_> = unaccepted_transfers
            .into_iter()
            .map(|hash| maybe_transfer(&snapshot, &hash).expect("Transfer"))
            .collect();

        WalletContentsProof {
            history,
            history_proof,
            unaccepted_transfers,
            unaccepted_transfers_proof,
        }
    }

    /// Checks the proof.
    ///
    /// # Return value
    ///
    /// Vectors with new events in wallet history and unaccepted incoming transfers.
    fn check(
        &self,
        wallet: &Wallet,
        query: &WalletQuery,
    ) -> Result<(Vec<FullEvent>, Vec<Transfer>), VerifyError> {
        // Verify wallet history.
        let proof_description = ProofDescription::History;
        let history_proof = self.history_proof.as_ref();
        let tx_hashes = if let Some(proof) = history_proof {
            proof
                .validate(*wallet.history_hash(), wallet.history_len())
                .map_err(|error| VerifyError::ListProof {
                    error,
                    proof_description,
                })?
        } else {
            vec![]
        };

        if tx_hashes.len() != self.history.len() {
            return Err(VerifyError::KeyMismatch(proof_description));
        }
        if let Some(&(start_index, ..)) = tx_hashes.first() {
            if start_index != query.start_history_at {
                return Err(VerifyError::KeyMismatch(proof_description));
            }
        }
        let stored_events = tx_hashes.into_iter().map(|(_, stored_event)| stored_event);
        for (stored_event, event) in stored_events.zip(&self.history) {
            if !event.corresponds_to(stored_event) {
                return Err(VerifyError::KeyMismatch(proof_description));
            }
        }

        // Verify unaccepted transfers.
        let proof_description = ProofDescription::UnacceptedTransfers;
        let transfer_hashes: HashSet<_> = self
            .unaccepted_transfers
            .iter()
            .map(|tx| tx.hash())
            .collect();

        let checked = self
            .unaccepted_transfers_proof
            .clone()
            .check()
            .map_err(|error| VerifyError::MapProof {
                error,
                proof_description,
            })?;
        if checked.merkle_root() != *wallet.unaccepted_transfers_hash() {
            return Err(VerifyError::ProofDisconnect(proof_description));
        }

        let hashes_in_proof: HashSet<_> = checked
            .entries()
            .into_iter()
            .map(|(&hash, _)| hash)
            .collect();
        if transfer_hashes != hashes_in_proof {
            return Err(VerifyError::KeyMismatch(proof_description));
        }

        Ok((self.history.clone(), self.unaccepted_transfers.clone()))
    }
}

// Required for conversions in `Service::wire`.
#[cfg_attr(feature = "cargo-clippy", allow(clippy::needless_pass_by_value))]
impl Api {
    /// Returns information about a single wallet. The information is supported with
    /// cryptographic proofs, allowing client applications to minimize trust in their server
    /// peers.
    pub fn wallet(state: &ServiceApiState, query: WalletQuery) -> api::Result<WalletProof> {
        let snapshot = state.snapshot();
        Ok(WalletProof::new(snapshot, &query))
    }

    /// Accepts transactions for processing.
    pub fn transaction(state: &ServiceApiState, tx: CryptoTransactions) -> api::Result<Hash> {
        use exonum::node::TransactionSend;

        let tx: Box<dyn Transaction> = tx.into();
        let tx_hash = tx.hash();
        state
            .sender()
            .send(tx)
            .map(|()| tx_hash)
            .map_err(|e| e.into())
    }
}
