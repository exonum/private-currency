//! This example spins a single-node blockchain network with several clients (i.e., entities
//! owning cryptocurrency accounts). The clients run in separate threads and connect to the node
//! via HTTP API both to send transactions and update their secret state, thus simulating
//! real client behavior.
//!
//! Run with
//!
//! ```shell
//! RUST_LOG=clients=info cargo run --example clients
//! ```

extern crate exonum;
#[macro_use]
extern crate log;
extern crate private_currency;
extern crate rand;
extern crate reqwest;
extern crate tempdir;

use exonum::{
    api::node::public::explorer::TransactionQuery,
    blockchain::{GenesisConfig, ValidatorKeys},
    crypto::{CryptoHash, Hash, PublicKey},
    explorer::TransactionInfo,
    node::{Node, NodeApiConfig, NodeConfig},
    storage::{DbOptions, RocksDB},
};
use private_currency::{
    api::{CheckedWalletProof, FullEvent, TrustAnchor, WalletProof, WalletQuery},
    transactions::{Accept, CreateWallet, Transfer},
    DebugEvent, DebuggerOptions, SecretState, Service as CurrencyService, CONFIG,
};
use rand::{seq::sample_iter, thread_rng, Rng};
use reqwest::Client as HttpClient;
use tempdir::TempDir;

use std::{
    cmp,
    collections::HashSet,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

/// Number of clients to emulate.
const CLIENT_COUNT: usize = 5;

#[derive(Debug, Clone)]
struct ClientEnv {
    keys: Arc<RwLock<HashSet<PublicKey>>>,
    trust_anchor: TrustAnchor,
}

impl ClientEnv {
    fn new<I>(consensus_keys: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        ClientEnv {
            keys: Arc::new(RwLock::new(HashSet::new())),
            trust_anchor: TrustAnchor::new(consensus_keys),
        }
    }

    fn add(&self, key: PublicKey) {
        self.keys.write().expect("write to keys").insert(key);
    }

    fn random_peer(&self, key: &PublicKey) -> Option<PublicKey> {
        let keys = self.keys.read().expect("read keys");
        if keys.len() <= 1 {
            None
        } else {
            let mut rng = thread_rng();
            Some(loop {
                let sample = sample_iter(&mut rng, keys.iter(), 1).expect("sample_iter")[0];
                if sample != key {
                    break *sample;
                }
            })
        }
    }
}

#[derive(Debug)]
struct Client {
    state: SecretState,
    http: HttpClient,
    events: Vec<FullEvent>,
    client_env: ClientEnv,
    unconfirmed_transfer: Option<Hash>,
}

impl Client {
    const WALLET_URL: &'static str =
        "http://127.0.0.1:8080/api/services/private_currency/v1/wallet";
    const TRANSACTION_URL: &'static str =
        "http://127.0.0.1:8080/api/services/private_currency/v1/transaction";
    const TX_STATUS_URL: &'static str = "http://127.0.0.1:8080/api/explorer/v1/transactions";

    fn new(client_env: ClientEnv) -> Self {
        let state = SecretState::with_random_keypair();
        client_env.add(*state.public_key());

        let client = Client {
            state,
            http: HttpClient::new(),
            events: vec![],
            client_env,
            unconfirmed_transfer: None,
        };
        client.log_info("started");
        client
    }

    fn tag(&self) -> String {
        let key = self.state.public_key().as_ref();
        format!("[{:02x}{:02x}{:02x}{:02x}]", key[0], key[1], key[2], key[3])
    }

    fn log_info(&self, info: &str) {
        info!("{} {}", self.tag(), info);
    }

    fn log_error(&self, error: &str) {
        error!("{} {}", self.tag(), error);
    }

    fn poll_history(&mut self) -> Vec<Transfer> {
        let query = WalletQuery {
            key: *self.state.public_key(),
            start_history_at: self.events.len() as u64,
        };
        let mut response = self
            .http
            .get(Self::WALLET_URL)
            .query(&query)
            .send()
            .expect("query wallet status");

        if response.status().is_success() {
            let wallet_proof: WalletProof = response.json().expect("cannot parse response");
            let CheckedWalletProof {
                wallet,
                history,
                unaccepted_transfers,
                ..
            } = wallet_proof
                .check(&self.client_env.trust_anchor, &query)
                .unwrap();
            let wallet = wallet.expect("wallet not found");

            for event in history {
                let old_balance = self.state.balance();

                match event {
                    FullEvent::CreateWallet(..) => {
                        self.log_info("received event: `CreateWallet`");
                        self.state.initialize();
                    }
                    FullEvent::Transfer(ref transfer) => {
                        self.log_info(&format!(
                            "received event: `Transfer`, tx_hash = {:?}",
                            transfer.hash()
                        ));
                        self.state.transfer(transfer);
                    }
                    FullEvent::Rollback(ref transfer) => {
                        self.log_info(&format!(
                            "received event: `Rollback`, tx_hash = {:?}",
                            transfer.hash()
                        ));
                        self.state.rollback(transfer);
                    }
                }

                self.log_info(&format!(
                    "updated balance: {} ({:+})",
                    self.state.balance(),
                    self.state.balance() as i64 - old_balance as i64,
                ));
                self.events.push(event);
            }

            assert!(self.state.corresponds_to(&wallet.info()));
            unaccepted_transfers
        } else {
            self.log_error(&format!("unexpected response: {:?}", response));
            vec![]
        }
    }

    fn accept_transfers(&self, transfers: &[Transfer]) {
        let accepts = transfers.iter().flat_map(|transfer| {
            if let Some(verified) = self.state.verify_transfer(transfer) {
                self.log_info(&format!(
                    "received transfer: {}, tx_hash = {:?}",
                    verified.value(),
                    transfer.hash()
                ));
                Some(verified.accept)
            } else {
                self.log_error(&format!(
                    "received incorrect transfer, tx_hash = {:?}",
                    transfer.hash()
                ));
                None
            }
        });

        for accept in accepts {
            self.send_accept(&accept);
        }
    }

    fn send_create_wallet(&self, create_wallet: &CreateWallet) {
        self.log_info(&format!(
            "sending `CreateWallet`, tx_hash = {:?}",
            create_wallet.hash()
        ));
        let mut response = self
            .http
            .post(Self::TRANSACTION_URL)
            .json(create_wallet)
            .send()
            .expect("send `CreateWallet`");
        let response: Hash = response.json().expect("transaction hash");
        assert_eq!(response, create_wallet.hash());
    }

    fn send_transfer(&mut self, transfer: &Transfer, amount: u64) {
        self.log_info(&format!(
            "sending `Transfer` (amount = {}) to {:?}, tx_hash = {:?}",
            amount,
            transfer.to(),
            transfer.hash()
        ));
        let mut response = self
            .http
            .post(Self::TRANSACTION_URL)
            .json(transfer)
            .send()
            .expect("send `Transfer`");
        let response: Hash = response.json().expect("transaction hash");
        assert_eq!(response, transfer.hash());
        self.unconfirmed_transfer = Some(transfer.hash());
    }

    fn poll_transfer_status(&mut self) {
        let tx_hash = *self
            .unconfirmed_transfer
            .as_ref()
            .expect("unconfirmed transfer");
        self.log_info(&format!("polling transfer status, tx_hash = {:?}", tx_hash));

        let mut response = self
            .http
            .get(Self::TX_STATUS_URL)
            .query(&TransactionQuery { hash: tx_hash })
            .send()
            .expect("transaction info");

        if !response.status().is_success() {
            self.log_error(&format!("transfer disappeared, tx_hash = {:?}", tx_hash));
            self.unconfirmed_transfer = None;
            return;
        }

        let response: TransactionInfo<Transfer> = response.json().expect("parse transaction info");
        if let Some(committed) = response.as_committed() {
            match committed.status() {
                Ok(_) => {
                    self.log_info(&format!("transfer committed, tx_hash = {:?}", tx_hash));
                }
                Err(e) => {
                    self.log_error(&format!(
                        "transfer failed, tx_hash = {:?}, reason: {}",
                        tx_hash, e
                    ));
                }
            }
            self.unconfirmed_transfer = None;
        }
    }

    fn send_accept(&self, accept: &Accept) {
        self.log_info(&format!(
            "sending `Accept` for transfer {:?}, tx_hash = {:?}",
            accept.transfer_id(),
            accept.hash()
        ));
        let mut response = self
            .http
            .post(Self::TRANSACTION_URL)
            .json(accept)
            .send()
            .expect("send `Accept`");
        let response: Hash = response.json().expect("transaction hash");
        assert_eq!(response, accept.hash());
    }

    fn run(mut self) {
        let mut rng = thread_rng();
        let mut sleep = move || {
            thread::sleep(Duration::from_millis(rng.gen_range(2_000, 3_000)));
        };

        let mut rng = thread_rng();
        let create_wallet = self.state.create_wallet();
        self.send_create_wallet(&create_wallet);
        sleep();

        loop {
            // Update our state.
            let unaccepted_transfers = self.poll_history();
            self.accept_transfers(&unaccepted_transfers);

            if self.unconfirmed_transfer.is_some() {
                self.poll_transfer_status();
            } else if let Some(peer) = self.client_env.random_peer(self.state.public_key()) {
                // Create a transfer to a random wallet.
                let amount = rng.gen_range(
                    CONFIG.min_transfer_amount,
                    cmp::min(10_000, self.state.balance()),
                );
                let transfer = self.state.create_transfer(amount, &peer, 10);
                self.send_transfer(&transfer, amount);
            }

            sleep();
            if rng.gen::<u8>() < 16 {
                // Simulate going offline for a while.
                self.log_info("going offline");
                thread::sleep(Duration::from_millis(7_000));
            }
        }
    }
}

fn node_config() -> NodeConfig {
    let (consensus_public_key, consensus_secret_key) = exonum::crypto::gen_keypair();
    let (service_public_key, service_secret_key) = exonum::crypto::gen_keypair();

    let validator_keys = ValidatorKeys {
        consensus_key: consensus_public_key,
        service_key: service_public_key,
    };
    let genesis = GenesisConfig::new(vec![validator_keys].into_iter());

    let api_address = "127.0.0.1:8080".parse().unwrap();
    let api_cfg = NodeApiConfig {
        public_api_address: Some(api_address),
        ..Default::default()
    };

    let peer_address = "127.0.0.1:2000".parse().unwrap();

    NodeConfig {
        listen_address: peer_address,
        service_public_key,
        service_secret_key,
        consensus_public_key,
        consensus_secret_key,
        genesis,
        external_address: peer_address,
        network: Default::default(),
        connect_list: Default::default(),
        api: api_cfg,
        mempool: Default::default(),
        services_configs: Default::default(),
        database: Default::default(),
    }
}

fn main() {
    exonum::helpers::init_logger().unwrap();

    let node_cfg = node_config();
    let consensus_keys = vec![node_cfg.consensus_public_key];

    let (service, debugger) = CurrencyService::debug(DebuggerOptions {
        check_invariants: true,
    });
    let debug_handle = thread::spawn(|| {
        for event in debugger {
            match event {
                DebugEvent::RolledBack { height, transfer } => {
                    warn!(
                        "rolled back transfer from {:?} to {:?}, tx_hash {:?}, at height {}",
                        transfer.from(),
                        transfer.to(),
                        transfer.hash(),
                        height
                    );
                }
            }
        }
    });

    // Start node thread.
    let handle = thread::spawn(|| {
        info!("Creating database...");
        let dir = TempDir::new("exonum").expect("tempdir");
        let db = RocksDB::open(dir.path(), &DbOptions::default()).expect("rocksdb");

        let node = Node::new(db, vec![Box::new(service)], node_cfg, None);
        info!("Starting a single node...");
        info!("Blockchain is ready for transactions!");
        node.run().unwrap();
    });

    thread::sleep(Duration::from_millis(2_000));
    info!("Starting clients");
    let client_env = ClientEnv::new(consensus_keys);
    let client_handles: Vec<_> = (0..CLIENT_COUNT)
        .map(|_| {
            let env = client_env.clone();
            thread::spawn(move || {
                let client = Client::new(env);
                client.run();
            })
        }).collect();

    client_handles
        .into_iter()
        .map(|handle| handle.join())
        .collect::<Result<(), _>>()
        .unwrap();
    handle.join().unwrap();
    debug_handle.join().unwrap();
}
