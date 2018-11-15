//! HTTP API for the service.

use exonum::{
    api::{self, ServiceApiState},
    blockchain::{Schema as CoreSchema, Transaction},
    crypto::{Hash, PublicKey},
    helpers::Height,
    messages::Message,
    storage::Snapshot,
};

use storage::{Event, EventTag, Schema, Wallet};
use transactions::{CreateWallet, CryptoTransactions, Transfer};

#[derive(Debug)]
pub enum Api {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletQuery {
    pub key: PublicKey,
    pub start_history_at: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "kebab-case")]
pub enum FullEvent {
    CreateWallet(CreateWallet),
    Transfer(Transfer),
    Rollback(Transfer),
}

impl FullEvent {
    fn from<T: AsRef<dyn Snapshot>>(event: Event, snapshot: T) -> Self {
        let schema = CoreSchema::new(snapshot);
        let transaction = schema
            .transactions()
            .get(event.transaction_hash())
            .expect("transaction");

        match event.tag() {
            tag if tag == EventTag::CreateWallet as u8 => {
                FullEvent::CreateWallet(CreateWallet::from_raw(transaction).expect("CreateWallet"))
            }
            tag if tag == EventTag::Transfer as u8 => {
                FullEvent::Transfer(Transfer::from_raw(transaction).expect("CreateWallet"))
            }
            tag if tag == EventTag::Rollback as u8 => {
                FullEvent::Rollback(Transfer::from_raw(transaction).expect("CreateWallet"))
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

        let core_schema = CoreSchema::new(&snapshot);
        let transactions = core_schema.transactions();
        let transfers: Vec<_> = schema
            .unaccepted_payments(&query.key)
            .into_iter()
            .map(|hash| {
                let transaction = transactions.get(&hash).expect("transaction");
                Transfer::from_raw(transaction).expect("Transfer")
            }).collect();
        Ok(UnacceptedTransfers {
            height: core_schema.height(),
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
