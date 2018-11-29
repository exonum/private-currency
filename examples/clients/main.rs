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

//! This example spins a single-node blockchain network with several clients (i.e., entities
//! owning cryptocurrency accounts). The clients run in separate threads and connect to the node
//! via HTTP API both to send transactions and update their secret state, thus simulating
//! real client behavior. The clients are honest (i.e., don't send invalid transactions
//! intentionally), but go "offline" periodically, thus potentially missing refund time-locks
//! for incoming transfers.
//!
//! Run with
//!
//! ```shell
//! cargo +nightly run --example clients -- <PARAMS>
//! ```
//!
//! Use `-h` or `--help` to get param description.

extern crate clap;
extern crate exonum;
#[macro_use]
extern crate log;
extern crate private_currency;
extern crate rand;
extern crate reqwest;
extern crate tempdir;

use clap::{App, Arg};
use exonum::{
    blockchain::{GenesisConfig, ValidatorKeys},
    crypto::CryptoHash,
    node::{Node, NodeApiConfig, NodeConfig},
    storage::{DbOptions, RocksDB},
};
use private_currency::{DebugEvent, DebuggerOptions, Service as CurrencyService, CONFIG};
use tempdir::TempDir;

use std::{env, thread, time::Duration};

mod client;
use client::{ClientConfig, ClientEnv};

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

fn parse_client_config() -> (usize, ClientConfig) {
    let client_count = Arg::with_name("client_count")
        .short("c")
        .long("clients")
        .takes_value(true)
        .value_name("CLIENTS")
        .default_value("5")
        .help("Number of clients to launch")
        .validator(|s| {
            let value: usize = s.parse().map_err(|_| "expected a number".to_owned())?;
            if value < 2 || value > 10 {
                return Err("expected a number between 2 and 10".to_owned());
            }
            Ok(())
        });
    let sleep_probability = Arg::with_name("sleep_probability")
        .short("s")
        .long("sleep-prob")
        .takes_value(true)
        .value_name("PROB")
        .default_value("0.1")
        .help("Probability for a client to go offline at any iteration of its routine")
        .validator(|s| {
            let value: f64 = s
                .parse()
                .map_err(|_| "expected a floating-point number".to_string())?;
            if value < 0.0 || value > 1.0 {
                return Err("expected a number between 0 and 1".to_string());
            }
            Ok(())
        });

    let sleep_duration = Arg::with_name("sleep_duration")
        .short("d")
        .long("sleep-dur")
        .takes_value(true)
        .value_name("DUR")
        .default_value("3000")
        .help("Sleep duration of a client, in milliseconds")
        .validator(|s| {
            let value: u64 = s.parse().map_err(|_| "expected a number".to_owned())?;
            if value > 60_000 {
                return Err("expected a number <=60,000".to_owned());
            }
            Ok(())
        });
    let time_lock = Arg::with_name("time_lock")
        .short("t")
        .long("timelock")
        .takes_value(true)
        .value_name("TTL")
        .default_value("10")
        .help("Rollback time-lock for transfers, in blockchain height")
        .validator(|s| {
            let value: u32 = s.parse().map_err(|_| "expected a number".to_owned())?;
            let bounds = CONFIG.rollback_delay_bounds;

            if value < bounds.start || value >= bounds.end {
                return Err("time-lock outside allowed bounds".to_owned());
            }
            Ok(())
        });

    let matches = App::new("Private cryptocurrency demo")
        .set_term_width(80)
        .author("The Exonum Team <exonum@bitfury.com>")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Demo for private cryptocurrency Exonum service")
        .after_help(
            "Demo launches a single-node blockchain network and a specified number \
             of clients. Each client then iterates the following routine: (1) receive updates \
             via `wallet` API endpoint; (2) create and broadcast a transfer to another client \
             chosen randomly; (3) maybe go to sleep. \
             Regardless of sleep probability / sleep duration config, \
             each client waits 2..3s on each iteration after step (3). \
             The demo runs indefinitely; hit Ctrl+C (or an equivalent) to terminate.",
        )
        .arg(client_count)
        .arg(sleep_probability)
        .arg(sleep_duration)
        .arg(time_lock)
        .get_matches();

    let client_count: usize = matches
        .value_of("client_count")
        .expect("no `client_count` param")
        .parse()
        .expect("`client_count` cannot be parsed");
    assert!(client_count >= 2 && client_count <= 10);

    let sleep_probability: f64 = matches
        .value_of("sleep_probability")
        .expect("no `sleep_probability` param")
        .parse()
        .expect("`sleep_probability` cannot be parsed");
    assert!(sleep_probability >= 0.0 && sleep_probability <= 1.0);

    let sleep_duration: u64 = matches
        .value_of("sleep_duration")
        .expect("no `sleep_duration` param")
        .parse()
        .expect("`sleep_duration` cannot be parsed");
    assert!(sleep_duration <= 60_000);
    let sleep_duration = Duration::from_millis(sleep_duration);

    let time_lock: u32 = matches
        .value_of("time_lock")
        .expect("no `time_lock` param")
        .parse()
        .expect("`time_lock` cannot be parsed");

    let config = ClientConfig {
        sleep_probability,
        sleep_duration,
        time_lock,
    };
    (client_count, config)
}

fn main() {
    env::set_var("RUST_LOG", "clients=info");
    exonum::helpers::init_logger().unwrap();

    let (client_count, client_config) = parse_client_config();
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
    info!("Starting clients with config {:?}", client_config);
    let client_env = ClientEnv::new(consensus_keys);
    client_env.run(client_count, client_config);
    handle.join().unwrap();
    debug_handle.join().unwrap();
}
