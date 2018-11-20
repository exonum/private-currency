//! HTTP API for the service.

use exonum::{
    api::{self, ServiceApiState},
    blockchain::{Block, BlockProof, Blockchain, Schema as CoreSchema, Transaction},
    crypto::{CryptoHash, Hash, PublicKey},
    helpers::Height,
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

pub use utils::{TrustAnchor, VerifyError as BlockVerifyError};

/// HTTP API for the private cryptocurrency service.
#[derive(Debug)]
pub enum Api {}

/// Query for `wallet` and `unaccepted_transfers` endpoints.
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
    CreateWallet(CreateWallet),
    Transfer(Transfer),
    Rollback(Transfer),
}

impl FullEvent {
    fn from<T: AsRef<dyn Snapshot>>(event: Event, snapshot: T) -> Self {
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

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletProof {
    block_proof: BlockProof,
    wallet_table_proof: MapProof<Hash, Hash>,
    wallet_proof: MapProof<PublicKey, Wallet>,
    #[serde(flatten)]
    wallet_contents: Option<WalletContentsProof>,
}

#[derive(Debug)]
pub struct CheckedWalletProof {
    pub block: Block,
    pub wallet: Option<Wallet>,
    pub history: Vec<FullEvent>,
    pub unaccepted_transfers: Vec<Transfer>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletContentsProof {
    history: Vec<FullEvent>,
    unaccepted_transfers: Vec<Transfer>,
    history_proof: Option<ListProof<Event>>,
    unaccepted_transfers_proof: MapProof<Hash, ()>,
}

#[derive(Debug, Fail)]
pub enum VerifyError {
    #[fail(display = "block verification failed: {}", _0)]
    Block(#[fail(cause)] BlockVerifyError),

    #[fail(
        display = "verifying `MapProof` for {} failed: {}",
        proof_description,
        error
    )]
    MapProof {
        #[fail(cause)]
        error: MapProofError,
        proof_description: ProofDescription,
    },

    #[fail(
        display = "verifying `ListProof` for {} failed: {:?}",
        proof_description,
        error
    )]
    ListProof {
        error: ListProofError,
        proof_description: ProofDescription,
    },

    #[fail(
        display = "Merkle proof for {} is disconnected from parent",
        _0
    )]
    ProofDisconnect(ProofDescription),

    #[fail(display = "Merkle proof for {} misses expected key", _0)]
    MissingKey(ProofDescription),

    #[fail(display = "Merkle proof and entries for {} do not match", _0)]
    KeyMismatch(ProofDescription),

    #[fail(display = "missing wallet contents")]
    NoContents,
}

#[derive(Debug, Clone, Copy)]
pub enum ProofDescription {
    WalletsTable,
    Wallet,
    Events,
    UnacceptedTransfers,
}

impl fmt::Display for ProofDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ProofDescription::*;

        match self {
            WalletsTable => f.write_str("wallets table"),
            Wallet => f.write_str("wallet"),
            Events => f.write_str("events"),
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
            .ok_or(VerifyError::MissingKey(proof_description))?;
        Ok(value.cloned())
    }

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
    fn new<T: AsRef<dyn Snapshot>>(snapshot: T, query: &WalletQuery) -> Self {
        let schema = Schema::new(&snapshot);

        // Get wallet history.
        let history_index = schema.history_index(&query.key);
        let start_history_at = query.start_history_at;
        let history: Vec<_> = history_index
            .iter_from(start_history_at)
            .map(|event| FullEvent::from(event, &snapshot))
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

    fn check(
        &self,
        wallet: &Wallet,
        query: &WalletQuery,
    ) -> Result<(Vec<FullEvent>, Vec<Transfer>), VerifyError> {
        // Verify wallet history.
        let proof_description = ProofDescription::Events;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletResponse {
    pub wallet: Wallet,
    pub history: Vec<FullEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnacceptedTransfers {
    pub height: Height,
    pub transfers: Vec<Transfer>,
}

impl Api {
    pub fn wallet(state: &ServiceApiState, query: WalletQuery) -> api::Result<WalletProof> {
        let snapshot = state.snapshot();
        Ok(WalletProof::new(snapshot, &query))
    }

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
