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

use exonum::{
    blockchain::{GenesisConfig, ValidatorKeys},
    crypto::{CryptoHash, Hash, PublicKey},
    helpers::Height,
    node::{Node, NodeApiConfig, NodeConfig},
    storage::MemoryDB,
};
use private_currency::{
    api::{FullEvent, UnacceptedTransfers, WalletQuery, WalletResponse},
    transactions::{Accept, CreateWallet, SecretState, Transfer},
    Service as CurrencyService,
};
use rand::{seq::sample_iter, thread_rng, Rng};
use reqwest::{Client as HttpClient, StatusCode};

use std::{
    cmp,
    collections::HashSet,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

#[derive(Debug, Clone)]
struct ClientEnv {
    keys: Arc<RwLock<HashSet<PublicKey>>>,
}

impl ClientEnv {
    fn new() -> Self {
        ClientEnv {
            keys: Arc::new(RwLock::new(HashSet::new())),
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
    blockchain_height: Height,
    events: Vec<FullEvent>,
    client_env: ClientEnv,
}

impl Client {
    const WALLET_URL: &'static str =
        "http://127.0.0.1:8080/api/services/private_currency/v1/wallet";
    const PENDING_TRANSFERS_URL: &'static str =
        "http://127.0.0.1:8080/api/services/private_currency/v1/unaccepted";
    const TRANSACTION_URL: &'static str =
        "http://127.0.0.1:8080/api/services/private_currency/v1/transaction";

    fn new(client_env: ClientEnv) -> Self {
        let state = SecretState::new();
        client_env.add(*state.public_key());

        let client = Client {
            state,
            http: HttpClient::new(),
            blockchain_height: Height(0),
            events: vec![],
            client_env,
        };
        client.log_info("started");
        client
    }

    fn tag(&self) -> String {
        let key = self.state.public_key().as_ref();
        format!("[{:x}{:x}{:x}{:x}]", key[0], key[1], key[2], key[3])
    }

    fn log_info(&self, info: &str) {
        info!("{} {}", self.tag(), info);
    }

    fn log_error(&self, error: &str) {
        error!("{} {}", self.tag(), error);
    }

    fn poll_history(&mut self) {
        let query = WalletQuery {
            key: *self.state.public_key(),
            start_history_at: Some(self.events.len() as u32),
        };
        let mut response = self
            .http
            .get(Self::WALLET_URL)
            .query(&query)
            .send()
            .expect("query wallet status");
        if response.status() == StatusCode::NOT_FOUND {
            self.log_info("wallet not found");
        } else if response.status().is_success() {
            let WalletResponse { wallet, history } =
                response.json().expect("cannot parse response");
            for event in history {
                let old_balance = self.state.balance();

                match event {
                    FullEvent::CreateWallet(..) => {
                        self.log_info("received event: `CreateWallet`");
                        self.state.initialize();
                    }
                    FullEvent::Transfer(ref transfer) => {
                        self.log_info("received event: `Transfer`");
                        self.state.transfer(transfer);
                    }
                    FullEvent::Rollback(ref transfer) => {
                        self.log_info("received event: `Rollback`");
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

            assert!(self.state.corresponds_to(&wallet));
        } else {
            self.log_error(&format!("unexpected response: {:?}", response));
        }
    }

    fn poll_unaccepted_transfers(&mut self) {
        let query = WalletQuery {
            key: *self.state.public_key(),
            start_history_at: Some(self.blockchain_height.next().0 as u32),
        };

        let mut response = self
            .http
            .get(Self::PENDING_TRANSFERS_URL)
            .query(&query)
            .send()
            .expect("query wallet status");
        if response.status() == StatusCode::NOT_FOUND {
            self.log_info("pending not found");
        } else if response.status().is_success() {
            let UnacceptedTransfers { height, transfers } =
                response.json().expect("cannot parse response");
            self.blockchain_height = height;
            let accepts = transfers.iter().flat_map(|transfer| {
                if let Some(verified) = self.state.verify_transfer(transfer) {
                    self.log_info(&format!(
                        "received transfer: {} (txhash = {:?})",
                        verified.value(),
                        transfer.hash()
                    ));
                    Some(verified.accept)
                } else {
                    self.log_error(&format!(
                        "received incorrect transfer (txhash = {:?})",
                        transfer.hash()
                    ));
                    None
                }
            });

            for accept in accepts {
                self.send_accept(&accept);
            }
        }
    }

    fn send_create_wallet(&self, create_wallet: &CreateWallet) {
        self.log_info(&format!(
            "sending `CreateWallet` (txhash = {:?})",
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

    fn send_transfer(&self, transfer: &Transfer, amount: u64) {
        self.log_info(&format!(
            "sending `Transfer` (amount = {}) to {:?} (txhash = {:?})",
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
    }

    fn send_accept(&self, accept: &Accept) {
        self.log_info(&format!(
            "sending `Accept` for transfer {:?} (txhash = {:?})",
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
            self.poll_history();

            // Create a transfer to a random wallet.
            if let Some(peer) = self.client_env.random_peer(self.state.public_key()) {
                let amount = rng.gen_range(0, cmp::min(10_000, self.state.balance()));
                if amount == 0 {
                    continue;
                }
                let transfer = self.state.create_transfer(amount, &peer, 50);
                self.send_transfer(&transfer, amount);
                sleep();
            }

            self.poll_unaccepted_transfers();
            sleep();
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

    let api_address = "0.0.0.0:8080".parse().unwrap();
    let api_cfg = NodeApiConfig {
        public_api_address: Some(api_address),
        ..Default::default()
    };

    let peer_address = "0.0.0.0:2000".parse().unwrap();

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

    // Start node thread.
    let handle = thread::spawn(|| {
        println!("Creating in-memory database...");
        let node = Node::new(
            MemoryDB::new(),
            vec![Box::new(CurrencyService)],
            node_config(),
            None,
        );
        println!("Starting a single node...");
        println!("Blockchain is ready for transactions!");
        node.run().unwrap();
    });

    thread::sleep(Duration::from_millis(2_000));
    println!("Starting clients");
    let client_env = ClientEnv::new();
    let client_handles: Vec<_> = (0..5)
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
}
