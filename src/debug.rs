//! Debugger for the service.

use exonum::{
    blockchain::{Schema as CoreSchema, ServiceContext},
    crypto::Hash,
    helpers::Height,
    storage::{Fork, KeySetIndex, Snapshot},
};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};

use storage::{maybe_transfer, EventTag, Schema};
use transactions::Transfer;

/// Name of table containing transfers rolled back at the previous height.
///
/// This table is filled by the debugger probe in `Service::before_commit` and then sent
/// to the debugger in `Service::after_commit`.
const ROLLED_BACK_TRANSFERS: &str = "private_currency.debug.rolled_back";

/// Event sent to the debugger.
#[derive(Debug, Clone, PartialEq)]
pub enum DebugEvent {
    /// A transfer has been rolled back.
    RolledBack {
        /// Transfer that has been rolled back.
        transfer: Transfer,
        /// Height at which the rollback occurred.
        height: Height,
    },
}

/// Debugger provides ability to connect to the service and retrieve information
/// useful for debugging.
///
/// Debugger allows to retrieve incoming events via `Iterator` implementation.
/// The iterator is blocking and should run on a separate thread.
///
/// # Examples
///
/// ```rust
/// # extern crate private_currency;
/// use private_currency::{Service, DebuggerOptions};
/// use std::thread;
///
/// let (service, debugger) = Service::debug(DebuggerOptions::default());
/// let handle = thread::spawn(|| {
///     for event in debugger {
///         println!("debug event: {:?}", event);
///     }
/// });
/// # drop(service);
/// # handle.join().unwrap();
/// ```
#[derive(Debug)]
pub struct Debugger {
    rx: mpsc::Receiver<DebugEvent>,
}

/// Debugger options.
#[derive(Debug, Clone, Default)]
pub struct DebuggerOptions {
    /// Check service invariants on `after_commit`.
    ///
    /// This is an expensive operation; it is *at least* linear w.r.t. the number of
    /// wallets in the system.
    pub check_invariants: bool,
}

impl Iterator for Debugger {
    type Item = DebugEvent;

    fn next(&mut self) -> Option<DebugEvent> {
        self.rx.recv().ok()
    }
}

#[derive(Debug)]
pub(crate) struct DebuggerProbe {
    tx: mpsc::SyncSender<DebugEvent>,
    shutdown: AtomicBool,
    options: DebuggerOptions,
}

impl DebuggerProbe {
    pub(crate) fn create_channel(size: usize, options: DebuggerOptions) -> (Self, Debugger) {
        let (tx, rx) = mpsc::sync_channel(size);
        let probe = DebuggerProbe {
            tx,
            shutdown: AtomicBool::new(false),
            options,
        };
        let debugger = Debugger { rx };
        (probe, debugger)
    }

    fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn on_before_commit(&self, fork: &mut Fork) {
        if self.is_shutdown() {
            return;
        }

        let mut schema = Schema::new(fork);
        schema.copy_rolled_back_transfers();
    }

    pub fn on_after_commit(&self, context: &ServiceContext) {
        if self.is_shutdown() {
            return;
        }
        let snapshot = context.snapshot();
        let height = context.height();
        let schema = Schema::new(&snapshot);

        if self.options.check_invariants {
            schema.check_invariants();
        }

        // Send rolled back transfers to the debugger.
        let rolled_back_transfers = schema.rolled_back_transfers();
        let result: Result<(), _> = rolled_back_transfers
            .iter()
            .map(|hash| maybe_transfer(&snapshot, &hash).expect("Transfer"))
            .map(|transfer| DebugEvent::RolledBack { transfer, height })
            .map(|message| self.tx.send(message).map_err(drop))
            .collect();
        if result.is_err() {
            // The debugger is shut down, we can shut down operations as well.
            self.shutdown();
        }
    }
}

impl<T: AsRef<dyn Snapshot>> Schema<T> {
    fn rolled_back_transfers(&self) -> KeySetIndex<&T, Hash> {
        KeySetIndex::new(ROLLED_BACK_TRANSFERS, &self.inner)
    }

    fn check_invariants(&self) {
        let wallets = self.wallets();
        for wallet in wallets.values() {
            let pk = wallet.public_key();
            let wallet_history = self.history_index(pk);

            // Check that summary in `wallet` corresponds to data in other indexes.
            assert_eq!(*wallet.history_hash(), wallet_history.merkle_root());
            assert_eq!(wallet.history_len(), wallet_history.len());
            assert_eq!(
                *wallet.unaccepted_transfers_hash(),
                self.unaccepted_transfers_index(pk).merkle_root()
            );

            // Check that past balances of the wallet are cached as expected.
            for i in wallet.last_send_index()..wallet.history_len() {
                assert!(self.past_balance(pk, i).is_some());
            }
            assert_eq!(
                self.past_balance(pk, wallet.history_len() - 1),
                Some(wallet.balance())
            );

            // Check the validity of `last_send_index` field.
            for event in wallet_history.iter_from(wallet.last_send_index() + 1) {
                if event.tag() == EventTag::Transfer as u8 {
                    let transfer =
                        maybe_transfer(&self.inner, event.transaction_hash()).expect("Transfer");
                    assert_eq!(
                        transfer.to(),
                        pk,
                        "outgoing transfer after indicated `last_send_index`"
                    );
                }
            }
        }
    }
}

impl<'a> Schema<&'a mut Fork> {
    fn rolled_back_transfers_mut(&mut self) -> KeySetIndex<&mut Fork, Hash> {
        KeySetIndex::new(ROLLED_BACK_TRANSFERS, self.inner)
    }

    fn copy_rolled_back_transfers(&mut self) {
        let height = CoreSchema::new(&self.inner).height();
        let transfer_ids = self.rollback_transfers(height);

        let mut rolled_back_transfers = self.rolled_back_transfers_mut();
        // Clear the index from the previous block.
        rolled_back_transfers.clear();

        for transfer_id in transfer_ids {
            rolled_back_transfers.insert(transfer_id);
        }
    }
}
