use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use near_primitives::{block::Tip, hash::CryptoHash, types::EpochId, utils::index_to_bytes};
use near_store::{
    db::RocksDB,
    DBCol::{ColBlockMisc, ColBlockPerHeight},
    Store, HEAD_KEY,
};

fn main() {
    println!("Hello, world!");
    let path = "/Users/michalski/.near_tmp/11/data";
    let db = Arc::new(RocksDB::new_read_only(path).unwrap());
    let store = Store::new(db);
    let tip: Tip = store.get_ser(ColBlockMisc, HEAD_KEY).unwrap().unwrap();

    for i in 1..100000 {
        if i == tip.height {
            break;
        }
        let key = index_to_bytes(tip.height - i);

        let value: Option<HashMap<EpochId, HashSet<CryptoHash>>> =
            store.get_ser(ColBlockPerHeight, &key).unwrap();

        if let Some(x) = value {
            if x.len() > 1 || x.iter().any(|f| f.1.len() > 1) {
                println!("{} Value: {:?}", tip.height - i, x);
            }
        }
        if i % 1000 == 0 {
            println!("{} {}", i, tip.height - i);
        }
    }
}
