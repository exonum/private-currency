//! Storage logic.

use exonum::{
    blockchain::Schema as CoreSchema,
    crypto::{CryptoHash, Hash, PublicKey},
    helpers::Height,
    messages::Message,
    storage::{Fork, KeySetIndex, ProofListIndex, ProofMapIndex, Snapshot},
};

use std::collections::HashSet;

use crypto::{enc, proofs::Commitment};
use transactions::{CreateWallet, Error, Transfer};

const WALLETS: &str = "private_currency.wallets";
const HISTORY: &str = "private_currency.history";
const UNACCEPTED_PAYMENTS: &str = "private_currency.unaccepted_payments";
const ROLLBACK_BY_HEIGHT: &str = "private_currency.rollback_by_height";

lazy_static! {
    static ref INITIAL_BALANCE: Commitment = Commitment::with_no_blinding(super::INITIAL_BALANCE);
}

encoding_struct! {
    struct Wallet {
        public_key: &PublicKey,
        balance: Commitment,
    }
}

encoding_struct! {
    #[derive(Eq, Hash)]
    struct Event {
        tag: u8,
        transaction_hash: &Hash,
    }
}

impl Event {
    pub fn transfer(id: &Hash) -> Self {
        Event::new(EventTag::Transfer as u8, id)
    }

    pub fn create_wallet(id: &Hash) -> Self {
        Event::new(EventTag::CreateWallet as u8, id)
    }

    pub fn rollback(id: &Hash) -> Self {
        Event::new(EventTag::Rollback as u8, id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum EventTag {
    CreateWallet = 0,
    Transfer = 1,
    Rollback = 2,
}

impl Wallet {
    pub fn encryption_key(&self) -> enc::PublicKey {
        enc::pk_from_ed25519(*self.public_key())
    }

    pub fn subtract_balance(&self, difference: &Commitment) -> Self {
        Wallet::new(self.public_key(), self.balance() - difference.clone())
    }

    pub fn add_balance(&self, difference: &Commitment) -> Self {
        Wallet::new(self.public_key(), self.balance() + difference.clone())
    }
}

pub(crate) fn maybe_create_wallet<T>(view: T, id: &Hash) -> Option<CreateWallet>
where
    T: AsRef<dyn Snapshot>,
{
    let core_schema = CoreSchema::new(view);
    let transaction = core_schema.transactions().get(id)?;
    CreateWallet::from_raw(transaction).ok()
}

pub(crate) fn maybe_transfer<T>(view: T, id: &Hash) -> Option<Transfer>
where
    T: AsRef<dyn Snapshot>,
{
    let core_schema = CoreSchema::new(view);
    let transaction = core_schema.transactions().get(id)?;
    Transfer::from_raw(transaction).ok()
}

#[derive(Debug)]
pub struct Schema<T> {
    inner: T,
}

impl<T: AsRef<dyn Snapshot>> Schema<T> {
    pub fn new(view: T) -> Self {
        Schema { inner: view }
    }

    pub fn state_hash(&self) -> Vec<Hash> {
        vec![]
    }

    pub fn wallets(&self) -> ProofMapIndex<&T, PublicKey, Wallet> {
        ProofMapIndex::new(WALLETS, &self.inner)
    }

    pub fn wallet(&self, public_key: &PublicKey) -> Option<Wallet> {
        self.wallets().get(public_key)
    }

    fn unaccepted_payments_index(&self, key: &PublicKey) -> ProofMapIndex<&T, Hash, ()> {
        ProofMapIndex::new_in_family(UNACCEPTED_PAYMENTS, key, &self.inner)
    }

    pub fn unaccepted_transfers(&self, key: &PublicKey) -> HashSet<Hash> {
        let index = self.unaccepted_payments_index(key);
        let hashes = index.keys().collect();
        hashes
    }

    pub(crate) fn history_index(&self, key: &PublicKey) -> ProofListIndex<&T, Event> {
        ProofListIndex::new_in_family(HISTORY, key, &self.inner)
    }

    pub fn history(&self, key: &PublicKey) -> Vec<Event> {
        let index = self.history_index(key);
        let hashes = index.iter().collect();
        hashes
    }

    fn rollback_index(&self, height: Height) -> KeySetIndex<&T, Hash> {
        let height = height.0;
        KeySetIndex::new_in_family(ROLLBACK_BY_HEIGHT, &height, &self.inner)
    }

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

    fn unaccepted_payments_mut(&mut self, key: &PublicKey) -> ProofMapIndex<&mut Fork, Hash, ()> {
        ProofMapIndex::new_in_family(UNACCEPTED_PAYMENTS, key, self.inner)
    }

    fn rollback_index_mut(&mut self, height: Height) -> KeySetIndex<&mut Fork, Hash> {
        let height = height.0;
        KeySetIndex::new_in_family(ROLLBACK_BY_HEIGHT, &height, self.inner)
    }

    pub(crate) fn create_wallet(
        &mut self,
        key: &PublicKey,
        tx: &CreateWallet,
    ) -> Result<(), Error> {
        if self.wallets().contains(key) {
            return Err(Error::WalletExists);
        }
        let wallet = Wallet::new(key, INITIAL_BALANCE.clone());
        self.wallets_mut().put(key, wallet);
        self.history_index_mut(key)
            .push(Event::create_wallet(&tx.hash()));
        Ok(())
    }

    pub(crate) fn update_sender(&mut self, sender: &Wallet, amount: &Commitment, tx: &Transfer) {
        let updated_sender = sender.subtract_balance(amount);
        self.wallets_mut().put(sender.public_key(), updated_sender);
        let event = Event::transfer(&tx.hash());
        self.history_index_mut(sender.public_key()).push(event);
    }

    pub(crate) fn add_unaccepted_payment(&mut self, receiver: &Wallet, transfer: &Transfer) {
        self.unaccepted_payments_mut(receiver.public_key())
            .put(&transfer.hash(), ());
        let rollback_height =
            CoreSchema::new(&self.inner).height().next().0 + transfer.rollback_delay() as u64;
        let rollback_height = Height(rollback_height);
        self.rollback_index_mut(rollback_height)
            .insert(transfer.hash());
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
        let rollback_height = Height(height.0 + transfer.rollback_delay() as u64);
        debug_assert!(rollback_height >= core_schema.height());
        rollback_height
    }

    pub(crate) fn accept_payment(
        &mut self,
        transfer: &Transfer,
        transfer_id: &Hash,
    ) -> Result<(), Error> {
        let receiver = transfer.to();
        // Update the receiver's wallet.
        let transfer_amount = transfer.amount();
        {
            let mut wallets = self.wallets_mut();
            let receiver_wallet = wallets.get(receiver).ok_or(Error::UnregisteredReceiver)?;
            let receiver_wallet = receiver_wallet.add_balance(&transfer_amount);
            wallets.put(receiver, receiver_wallet);
        }
        let event = Event::transfer(transfer_id);
        self.history_index_mut(receiver).push(event);

        // Remove the transfer from the unaccepted list.
        {
            let mut payments = self.unaccepted_payments_mut(receiver);
            if !payments.contains(transfer_id) {
                return Err(Error::UnknownTransfer);
            }
            payments.remove(transfer_id);
        }

        // Remove the transfer from the rollback index.
        let rollback_height = self.rollback_height(transfer_id);
        let mut rollback_set = self.rollback_index_mut(rollback_height);
        debug_assert!(rollback_set.contains(transfer_id));
        rollback_set.remove(transfer_id);

        Ok(())
    }

    fn rollback_single(&mut self, transfer: &Transfer, transfer_hash: &Hash) {
        {
            // Refund sender.
            let mut wallets = self.wallets_mut();
            let sender_wallet = wallets.get(transfer.from()).expect("sender");
            let amount = transfer.amount();
            let sender_wallet = sender_wallet.add_balance(&amount);
            wallets.put(transfer.from(), sender_wallet);
        }
        // Update sender history.
        let event = Event::rollback(transfer_hash);
        self.history_index_mut(transfer.from()).push(event);
    }

    /// Rolls back unaccepted transfers that expire at the current height.
    pub(crate) fn do_rollback(&mut self) {
        let height = CoreSchema::new(&self.inner).height();
        let transfer_ids = self.rollback_transfers(height);

        for hash in &transfer_ids {
            let transfer = CoreSchema::new(&self.inner)
                .transactions()
                .get(hash)
                .expect("transfer");
            let transfer = Transfer::from_raw(transfer).expect("parse transfer");
            self.rollback_single(&transfer, hash);
            self.rollback_index_mut(height).remove(hash);
        }

        // FIXME: uncomment once https://github.com/exonum/exonum/pull/1042 lands.
        //self.rollback_index_mut(height).clear();
    }
}
