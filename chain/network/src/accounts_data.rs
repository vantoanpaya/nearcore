use std::collections::HashMap;
use std::sync::Arc;
use near_crypto::{PublicKey};
use near_primitives::types::{AccountId,EpochId};
use crate::network_protocol::SignedAccountData;
use near_network_primitives::types::EpochInfo;
use parking_lot::{Mutex,RwLock};

struct Account {
    key: PublicKey,
    data: Mutex<Option<SignedAccountData>>,
}

struct Epoch(HashMap<AccountId,Account>);

impl Epoch {
    fn new(keys:&HashMap<AccountId,PublicKey>) -> Self {
        Self(keys.iter().map(|(id,key)|(id.clone(),Account{
            key:key.clone(), data: Mutex::new(None),
        })).collect())
    }
}

pub(crate) enum Error {
    InvalidSignature,
}

impl Epoch {
    /// Returns Some(d) if insertion succeeded (i.e. if d was a new and valid value).
    pub fn try_insert(&self, d:SignedAccountData) -> Result<Option<SignedAccountData>,Error> {
        // TODO: we should impose a limit on size of d here.
        let x = match self.0.get(&d.account_id) {
            Some(x) => x,
            None => return Ok(None),
        };
        let lock_if_new = || {
            let l = x.data.lock();
            match &*l {
                Some(v) if v.timestamp>=d.timestamp => None,
                _ => Some(l),
            }
        };
        if lock_if_new().is_none() { return Ok(None) }
        if !d.payload().verify(&x.key) {
            return Err(Error::InvalidSignature);
        }
        Ok(lock_if_new().map(|mut v|{ *v = Some(d.clone()); d }))
    }
}

pub struct Inner {
    epochs: RwLock<HashMap<EpochId,Arc<Epoch>>>,
    runtime: tokio::runtime::Runtime,
}

#[derive(Clone)]
pub(crate) struct AccountsData(Arc<Inner>);

impl AccountsData {
    pub fn new() -> Self {
        Self(Arc::new(Inner{
            epochs: RwLock::new(HashMap::new()),
            runtime: tokio::runtime::Runtime::new().unwrap(),
        }))
    }

    pub fn set_epochs(&self, new_epochs:Vec<&EpochInfo>) -> bool {
        let mut epochs = self.0.epochs.write();
        epochs.retain(|id,_|new_epochs.iter().any(|e|&e.id==id));
        let mut has_new = false;
        for e in new_epochs {
            epochs.entry(e.id.clone()).or_insert_with(||{
                has_new = true;
                Arc::new(Epoch::new(&e.priority_accounts))
            });
        }
        has_new
    }

    pub async fn insert(&self, data:Vec<SignedAccountData>) -> Result<Vec<SignedAccountData>,Error> {
        // spawn insertions on a dedicated runtime.
        let mut futures = vec![];
        let epochs = self.0.epochs.read();
        for d in data {
            if let Some(e) = epochs.get(&d.epoch_id).cloned() {
                futures.push(self.0.runtime.spawn(async move { e.try_insert(d) }));
            }
        }
        drop(epochs);

        // await completion of insertions.
        let mut new = vec![];
        for f in futures {
            if let Some(d) = f.await.unwrap()? {
                new.push(d);
            }
        }
        Ok(new)
    }

    pub fn dump(&self) -> Vec<SignedAccountData> {
        self.0.epochs.read().values().map(|e|&e.0).flatten().filter_map(|(_,a)|a.data.lock().clone()).collect()
    }
}
