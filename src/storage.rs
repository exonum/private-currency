//! Storage logic for the service.

use exonum::{
    blockchain::Schema as CoreSchema,
    crypto::{CryptoHash, Hash, PublicKey},
    helpers::Height,
    messages::Message,
    storage::{Fork, KeySetIndex, ProofListIndex, ProofMapIndex, Snapshot, SparseListIndex},
};

use std::collections::{HashMap, HashSet};

use super::CONFIG;
use crypto::{enc, Commitment};
use transactions::{CreateWallet, Error, Transfer};

const WALLETS: &str = "private_currency.wallets";
const HISTORY: &str = "private_currency.history";
const UNACCEPTED_PAYMENTS: &str = "private_currency.unaccepted_payments";
const ROLLBACK_BY_HEIGHT: &str = "private_currency.rollback_by_height";
const PAST_BALANCES: &str = "private_currency.past_balances";

lazy_static! {
    /// Commitment to the initial balance of a wallet.
    ///
    /// We don't use a blinding factor for the commitment since we assume
    /// that the initial balance of a wallet is a public constant.
    static ref INITIAL_BALANCE: Commitment = Commitment::with_no_blinding(CONFIG.initial_balance);
}

encoding_struct! {
    /// Wallet summary.
    struct Wallet {
        /// Ed25519 public key associated with the wallet. Transactions originating from the wallet
        /// need to be digitally signed with the paired secret key.
        public_key: &PublicKey,
        /// Commitment to the current wallet balance.
        balance: Commitment,
        /// Number of entries in the wallet history.
        history_len: u64,
        /// Index of the last outgoing transfer in the wallet history.
        last_send_index: u64,
        /// Merkle root of the wallet history list.
        history_hash: &Hash,
        /// Merkle root of the unaccepted incoming transfers.
        unaccepted_transfers_hash: &Hash,
    }
}

encoding_struct! {
    /// Storage representation of an event concerning a wallet.
    ///
    /// # See also
    ///
    /// - [HTTP API representation](::api::FullEvent)
    #[derive(Eq, Hash)]
    struct Event {
        /// Event tag.
        tag: u8,
        /// Hash of a transaction associated with the event.
        transaction_hash: &Hash,
    }
}

impl Event {
    /// Creates a new transfer event.
    pub fn transfer(id: &Hash) -> Self {
        Event::new(EventTag::Transfer as u8, id)
    }

    /// Creates a new wallet initialization event.
    pub fn create_wallet(id: &Hash) -> Self {
        Event::new(EventTag::CreateWallet as u8, id)
    }

    /// Creates a new transfer rollback event.
    pub fn rollback(id: &Hash) -> Self {
        Event::new(EventTag::Rollback as u8, id)
    }
}

/// Tag used in `Event`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum EventTag {
    /// Wallet initialization.
    CreateWallet = 0,
    /// Transfer to or from the wallet.
    Transfer = 1,
    /// Transfer rollback.
    Rollback = 2,
}

/// Gist of information about the wallet, stripped of auxiliary data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletInfo {
    /// Ed25519 public key associated with the wallet. Transactions originating from the wallet
    /// need to be digitally signed with the paired secret key.
    pub public_key: PublicKey,
    /// Commitment to the current wallet balance.
    pub balance: Commitment,
}

impl WalletInfo {
    /// Computes the encryption key associated with the wallet.
    pub fn encryption_key(&self) -> enc::PublicKey {
        enc::pk_from_ed25519(self.public_key)
    }
}

impl Wallet {
    fn initialize(key: &PublicKey, history_hash: &Hash) -> Self {
        Wallet::new(
            key,
            INITIAL_BALANCE.clone(),
            1,
            0,
            history_hash,
            &Hash::zero(),
        )
    }

    /// Retrieves the wallet summary.
    pub fn info(&self) -> WalletInfo {
        WalletInfo {
            public_key: *self.public_key(),
            balance: self.balance(),
        }
    }

    /// Computes the encryption key associated with the wallet.
    pub fn encryption_key(&self) -> enc::PublicKey {
        enc::pk_from_ed25519(*self.public_key())
    }

    fn subtract_balance(&self, difference: &Commitment, history_hash: &Hash) -> Self {
        Wallet::new(
            self.public_key(),
            self.balance() - difference.clone(),
            self.history_len() + 1,
            self.history_len(), // `last_send_index` field is updated
            history_hash,
            self.unaccepted_transfers_hash(),
        )
    }

    fn add_balance(&self, difference: &Commitment, history_hash: &Hash) -> Self {
        Wallet::new(
            self.public_key(),
            self.balance() + difference.clone(),
            self.history_len() + 1,
            self.last_send_index(), // unchanged: this is an incoming transfer or a refund
            history_hash,
            self.unaccepted_transfers_hash(),
        )
    }

    fn set_unaccepted_transfers_hash(&self, hash: &Hash) -> Self {
        Wallet::new(
            self.public_key(),
            self.balance(),
            self.history_len(),
            self.last_send_index(),
            self.history_hash(),
            hash,
        )
    }
}

/// Loads a `CreateWallet` transaction with the specified hash from a storage snapshot.
///
/// # Return value
///
/// If a transaction with the specified hash does not exist in the blockchain or is not
/// a `CreateWallet`, the function returns `None`.
pub(crate) fn maybe_create_wallet<T>(view: T, id: &Hash) -> Option<CreateWallet>
where
    T: AsRef<dyn Snapshot>,
{
    let core_schema = CoreSchema::new(view);
    if !core_schema.transactions_locations().contains(id) {
        return None;
    }
    let transaction = core_schema.transactions().get(id)?;
    CreateWallet::from_raw(transaction).ok()
}

/// Loads a `Transfer` transaction with the specified hash from a storage snapshot.
///
/// # Return value
///
/// If a transaction with the specified hash does not exist in the blockchain or is not
/// a `Transfer`, the function returns `None`.
pub(crate) fn maybe_transfer<T>(view: T, id: &Hash) -> Option<Transfer>
where
    T: AsRef<dyn Snapshot>,
{
    let core_schema = CoreSchema::new(view);
    if !core_schema.transactions_locations().contains(id) {
        return None;
    }
    let transaction = core_schema.transactions().get(id)?;
    Transfer::from_raw(transaction).ok()
}

/// Schema for the private currency service.
#[derive(Debug)]
pub struct Schema<T> {
    pub(crate) inner: T,
}

impl<T: AsRef<dyn Snapshot>> Schema<T> {
    /// Creates a schema based on the storage view.
    pub fn new(view: T) -> Self {
        Schema { inner: view }
    }

    /// Returns the state hash of the service.
    ///
    /// The state hash directly commits to a single table of the service, wallets.
    /// Other Merkelized tables (wallet histories and unaccepted transfers) are connected
    /// to the state via fields in [`Wallet`] records.
    ///
    /// [`Wallet`]: self::Wallet
    pub fn state_hash(&self) -> Vec<Hash> {
        vec![self.wallets().merkle_root()]
    }

    /// Returns the mapping of public keys to wallets.
    pub fn wallets(&self) -> ProofMapIndex<&T, PublicKey, Wallet> {
        ProofMapIndex::new(WALLETS, &self.inner)
    }

    /// Loads a wallet with the specified `public_key`.
    pub fn wallet(&self, public_key: &PublicKey) -> Option<Wallet> {
        self.wallets().get(public_key)
    }

    pub(crate) fn unaccepted_transfers_index(
        &self,
        key: &PublicKey,
    ) -> ProofMapIndex<&T, Hash, ()> {
        ProofMapIndex::new_in_family(UNACCEPTED_PAYMENTS, key, &self.inner)
    }

    /// Returns all unaccepted incoming transfers for the account associated
    /// with the given public `key`.
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::let_and_return))]
    pub fn unaccepted_transfers(&self, key: &PublicKey) -> HashSet<Hash> {
        let index = self.unaccepted_transfers_index(key);
        let hashes = index.keys().collect();
        hashes
    }

    pub(crate) fn history_index(&self, key: &PublicKey) -> ProofListIndex<&T, Event> {
        ProofListIndex::new_in_family(HISTORY, key, &self.inner)
    }

    /// Returns all history entries for the specified account.
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::let_and_return))]
    pub fn history(&self, key: &PublicKey) -> Vec<Event> {
        let index = self.history_index(key);
        let hashes = index.iter().collect();
        hashes
    }

    fn past_balances(&self, key: &PublicKey) -> SparseListIndex<&T, Commitment> {
        SparseListIndex::new_in_family(PAST_BALANCES, key, &self.inner)
    }

    /// Returns a past balance of a wallet.
    pub fn past_balance(&self, key: &PublicKey, index: u64) -> Option<Commitment> {
        self.past_balances(key).get(index)
    }

    fn rollback_index(&self, height: Height) -> KeySetIndex<&T, Hash> {
        let height = height.0;
        KeySetIndex::new_in_family(ROLLBACK_BY_HEIGHT, &height, &self.inner)
    }

    /// Returns hashes for all unaccepted transfers that should rolled back at
    /// the specified blockchain height.
    #[doc(hidden)]
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::let_and_return))]
    pub fn rollback_transfers(&self, height: Height) -> Vec<Hash> {
        let index = self.rollback_index(height);
        let hashes = index.iter().collect();
        hashes
    }
}

impl<'a> Schema<&'a mut Fork> {
    fn wallets_mut(&mut self) -> ProofMapIndex<&mut Fork, PublicKey, Wallet> {
        ProofMapIndex::new(WALLETS, self.inner)
    }

    fn history_index_mut(&mut self, key: &PublicKey) -> ProofListIndex<&mut Fork, Event> {
        ProofListIndex::new_in_family(HISTORY, key, self.inner)
    }

    fn unaccepted_transfers_mut(&mut self, key: &PublicKey) -> ProofMapIndex<&mut Fork, Hash, ()> {
        ProofMapIndex::new_in_family(UNACCEPTED_PAYMENTS, key, self.inner)
    }

    fn rollback_index_mut(&mut self, height: Height) -> KeySetIndex<&mut Fork, Hash> {
        let height = height.0;
        KeySetIndex::new_in_family(ROLLBACK_BY_HEIGHT, &height, self.inner)
    }

    fn past_balances_mut(&mut self, key: &PublicKey) -> SparseListIndex<&mut Fork, Commitment> {
        SparseListIndex::new_in_family(PAST_BALANCES, key, self.inner)
    }

    pub(crate) fn create_wallet(
        &mut self,
        key: &PublicKey,
        tx: &CreateWallet,
    ) -> Result<(), Error> {
        if self.wallets().contains(key) {
            return Err(Error::WalletExists);
        }

        self.history_index_mut(key)
            .push(Event::create_wallet(&tx.hash()));
        let history_hash = self.history_index(key).merkle_root();
        let wallet = Wallet::initialize(key, &history_hash);
        self.past_balances_mut(key).set(0, wallet.balance());
        self.wallets_mut().put(key, wallet);
        Ok(())
    }

    pub(crate) fn update_sender(&mut self, sender: &Wallet, amount: &Commitment, tx: &Transfer) {
        let key = sender.public_key();
        let event = Event::transfer(&tx.hash());
        self.history_index_mut(key).push(event);
        let history_hash = self.history_index(key).merkle_root();
        let updated_sender = sender.subtract_balance(amount, &history_hash);

        {
            // Remove all previously cached past balances and record the newest one.
            // FIXME: update once https://github.com/exonum/exonum/pull/1042 lands.
            // self.past_balances_mut(key).clear();
            let mut past_balances = self.past_balances_mut(key);
            let indices: Vec<_> = past_balances.indices().collect();
            for i in indices {
                past_balances.remove(i);
            }
            past_balances.set(updated_sender.history_len() - 1, updated_sender.balance());
        }

        self.wallets_mut().put(sender.public_key(), updated_sender);
    }

    pub(crate) fn add_unaccepted_payment(&mut self, receiver: &Wallet, transfer: &Transfer) {
        let unaccepted_transfers_hash = {
            let mut unaccepted_transfers = self.unaccepted_transfers_mut(receiver.public_key());
            unaccepted_transfers.put(&transfer.hash(), ());
            unaccepted_transfers.merkle_root()
        };

        let rollback_height =
            CoreSchema::new(&self.inner).height().next().0 + u64::from(transfer.rollback_delay());
        let rollback_height = Height(rollback_height);
        self.rollback_index_mut(rollback_height)
            .insert(transfer.hash());

        let receiver = receiver.set_unaccepted_transfers_hash(&unaccepted_transfers_hash);
        let receiver_pk = *receiver.public_key();
        self.wallets_mut().put(&receiver_pk, receiver);
    }

    fn rollback_height(&self, transfer_id: &Hash) -> Height {
        let core_schema = CoreSchema::new(&self.inner);
        let tx_location = core_schema
            .transactions_locations()
            .get(transfer_id)
            .expect("transfer");
        let height = tx_location.block_height();
        let transfer = core_schema
            .transactions()
            .get(transfer_id)
            .expect("transfer");
        let transfer = Transfer::from_raw(transfer).expect("parse transfer");
        let rollback_height = Height(height.0 + u64::from(transfer.rollback_delay()));
        debug_assert!(rollback_height >= core_schema.height());
        rollback_height
    }

    pub(crate) fn accept_payment(
        &mut self,
        transfer: &Transfer,
        transfer_id: &Hash,
    ) -> Result<(), Error> {
        let receiver = transfer.to();

        let event = Event::transfer(transfer_id);
        self.history_index_mut(receiver).push(event);
        let history_hash = self.history_index(receiver).merkle_root();

        // Remove the transfer from the unaccepted list.
        let unaccepted_transfers_hash = {
            let mut payments = self.unaccepted_transfers_mut(receiver);
            if !payments.contains(transfer_id) {
                return Err(Error::UnknownTransfer);
            }
            payments.remove(transfer_id);
            payments.merkle_root()
        };

        // Update the receiver's wallet.
        let transfer_amount = transfer.amount();
        let receiver_wallet = self.wallet(receiver).ok_or(Error::UnregisteredReceiver)?;
        let receiver_wallet = receiver_wallet
            .add_balance(&transfer_amount, &history_hash)
            .set_unaccepted_transfers_hash(&unaccepted_transfers_hash);

        self.past_balances_mut(receiver)
            .push(receiver_wallet.balance());
        self.wallets_mut().put(receiver, receiver_wallet);

        // Remove the transfer from the rollback index.
        let rollback_height = self.rollback_height(transfer_id);
        let mut rollback_set = self.rollback_index_mut(rollback_height);
        debug_assert!(rollback_set.contains(transfer_id));
        rollback_set.remove(transfer_id);

        Ok(())
    }

    fn rollback_single(&mut self, transfer: &Transfer, transfer_hash: &Hash) {
        // Update sender history.
        let event = Event::rollback(transfer_hash);
        self.history_index_mut(transfer.from()).push(event);
        let history_hash = self.history_index(transfer.from()).merkle_root();

        let sender_wallet = {
            // Refund sender.
            let mut wallets = self.wallets_mut();
            let sender_wallet = wallets.get(transfer.from()).expect("sender");
            let amount = transfer.amount();
            let sender_wallet = sender_wallet.add_balance(&amount, &history_hash);
            wallets.put(transfer.from(), sender_wallet.clone());
            sender_wallet
        };
        // Remember the balance.
        self.past_balances_mut(transfer.from())
            .push(sender_wallet.balance());
    }

    /// Rolls back unaccepted transfers that expire at the current height.
    pub(crate) fn do_rollback(&mut self) {
        let height = CoreSchema::new(&self.inner).height();
        let transfer_ids = self.rollback_transfers(height);

        let mut updated_unaccepted_transfers = HashMap::new();
        for hash in &transfer_ids {
            let transfer = maybe_transfer(&self.inner, hash).expect("Transfer");
            self.rollback_single(&transfer, hash);
            self.rollback_index_mut(height).remove(hash);

            let mut unaccepted_transfers = self.unaccepted_transfers_mut(transfer.to());
            unaccepted_transfers.remove(hash);
            updated_unaccepted_transfers.insert(*transfer.to(), unaccepted_transfers.merkle_root());
        }

        let mut wallets = self.wallets_mut();
        for (key, hash) in updated_unaccepted_transfers {
            let wallet = wallets.get(&key).expect("receiver's wallet");
            let wallet = wallet.set_unaccepted_transfers_hash(&hash);
            wallets.put(&key, wallet);
        }

        // FIXME: uncomment once https://github.com/exonum/exonum/pull/1042 lands.
        //self.rollback_index_mut(height).clear();
    }
}
