//! HTTP API for the service.

use exonum::{
    api::{self, ServiceApiState},
    blockchain::{Schema as CoreSchema, Transaction},
    crypto::{Hash, PublicKey},
    helpers::Height,
    storage::Snapshot,
};

use storage::{maybe_create_wallet, maybe_transfer, Event, EventTag, Schema, Wallet};
use transactions::{CreateWallet, CryptoTransactions, Transfer};

/// HTTP API for the private cryptocurrency service.
#[derive(Debug)]
pub enum Api {}

/// Query for `wallet` and `unaccepted_transfers` endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletQuery {
    /// Public key of the account to check.
    pub key: PublicKey,

    /// The starting point of historic information.
    ///
    /// For the `wallet` endpoint, this is the starting index for the user's list of events.
    /// For `unaccepted_transfers`, this value is the minimum blockchain height for
    /// unaccepted transfers to the user that should be fetched.
    pub start_history_at: Option<u32>,
}

/// Event changing balance of a wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn wallet(state: &ServiceApiState, query: WalletQuery) -> api::Result<WalletResponse> {
        let snapshot = state.snapshot();
        let schema = Schema::new(&snapshot);
        schema
            .wallet(&query.key)
            .map(|wallet| {
                let history_index = schema.history_index(&query.key);
                let start_history_at = query.start_history_at.unwrap_or_default() as u64;
                let history = history_index
                    .iter_from(start_history_at)
                    .map(|event| FullEvent::from(event, &snapshot))
                    .collect();
                WalletResponse { wallet, history }
            }).ok_or_else(|| api::Error::NotFound("wallet".to_owned()))
    }

    pub fn unaccepted_transfers(
        state: &ServiceApiState,
        query: WalletQuery,
    ) -> api::Result<UnacceptedTransfers> {
        let snapshot = state.snapshot();
        let schema = Schema::new(&snapshot);

        if schema.wallet(&query.key).is_none() {
            return Err(api::Error::NotFound("wallet".to_owned()));
        }

        let transfers: Vec<_> = schema
            .unaccepted_transfers(&query.key)
            .into_iter()
            .map(|hash| maybe_transfer(&snapshot, &hash).expect("Transfer"))
            .collect();
        Ok(UnacceptedTransfers {
            height: CoreSchema::new(&snapshot).height(),
            transfers,
        })
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
