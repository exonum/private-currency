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

use exonum::{
    api::node::public::explorer::TransactionQuery,
    crypto::{CryptoHash, Hash, PublicKey},
    explorer::TransactionInfo,
};
use private_currency::{
    api::{CheckedWalletProof, FullEvent, TrustAnchor, WalletProof, WalletQuery},
    transactions::{Accept, CreateWallet, Transfer},
    SecretState, CONFIG,
};
use rand::{seq::sample_iter, thread_rng, Rng};
use reqwest::Client as HttpClient;

use std::{
    cmp,
    collections::HashSet,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

#[derive(Debug, Clone, Copy)]
pub struct ClientConfig {
    pub sleep_probability: f64,
    pub sleep_duration: Duration,
    pub time_lock: u32,
}

#[derive(Debug, Clone)]
pub struct ClientEnv {
    keys: Arc<RwLock<HashSet<PublicKey>>>,
    trust_anchor: TrustAnchor,
}

impl ClientEnv {
    pub fn new<I>(consensus_keys: I) -> Self
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

    pub fn run(self, client_count: usize, config: ClientConfig) {
        let client_handles: Vec<_> = (0..client_count)
            .map(|_| {
                let env = self.clone();
                thread::spawn(move || {
                    let client = Client::new(env, config);
                    client.run();
                })
            })
            .collect();

        client_handles
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Result<(), _>>()
            .unwrap();
    }
}

#[derive(Debug)]
struct Client {
    state: SecretState,
    http: HttpClient,
    events: Vec<FullEvent>,
    client_env: ClientEnv,
    unconfirmed_transfer: Option<Hash>,
    config: ClientConfig,
}

impl Client {
    const WALLET_URL: &'static str =
        "http://127.0.0.1:8080/api/services/private_currency/v1/wallet";
    const TRANSACTION_URL: &'static str =
        "http://127.0.0.1:8080/api/services/private_currency/v1/transaction";
    const TX_STATUS_URL: &'static str = "http://127.0.0.1:8080/api/explorer/v1/transactions";

    fn new(client_env: ClientEnv, config: ClientConfig) -> Self {
        let state = SecretState::with_random_keypair();
        client_env.add(*state.public_key());

        let client = Client {
            state,
            http: HttpClient::new(),
            events: vec![],
            client_env,
            unconfirmed_transfer: None,
            config,
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

        let config = self.config;

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
                let transfer = self.state.create_transfer(amount, &peer, config.time_lock);
                self.send_transfer(&transfer, amount);
            }

            sleep();
            if rng.gen::<f64>() < config.sleep_probability {
                // Simulate going offline for a while.
                self.log_info("going offline");
                thread::sleep(config.sleep_duration);
            }
        }
    }
}
