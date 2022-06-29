use std::collections::HashMap;
use std::sync::Arc;
use near_crypto::{PublicKey};
use near_primitives::types::{AccountId,EpochId};
use crate::network_protocol::SignedValidator;
use near_network_primitives::types::EpochInfo;
use parking_lot::Mutex;

struct Account {
    key: PublicKey,
    data: Mutex<Option<SignedValidator>>,
}

struct Epoch(HashMap<AccountId,Account>);

pub(crate) enum Error {
    InvalidSignature,
}

impl Epoch {
    pub fn insert(&self, d:&SignedValidator) -> Result<bool,Error> {
        // TODO: we should impose a limit on size of d here.
        let x = match self.0.get(&d.account_id) {
            Some(x) => x,
            None => return Ok(false),
        };
        let lock_if_new = || {
            let l = x.data.lock();
            match &*l {
                Some(v) if v.timestamp>=d.timestamp => None,
                _ => Some(l),
            }
        };
        if lock_if_new().is_none() { return Ok(false) }
        // TODO(gprusak): probably should be moved to a dedicated runtime.
        if !d.payload().verify(&x.key) {
            return Err(Error::InvalidSignature);
        }
        Ok(lock_if_new().map(|mut v| *v = Some(d.clone())).is_some())
    }
}

#[derive(Default)]
pub(crate) struct AccountsData(HashMap<EpochId,Arc<Epoch>>);

impl AccountsData {
    pub fn set_epochs(&mut self, epochs:Vec<&EpochInfo>) -> bool {
        self.0.retain(|id,_|epochs.iter().any(|e|&e.id==id));
        let mut has_new = false;
        for e in epochs {
            self.0.entry(e.id.clone()).or_insert_with(||{
                has_new = true;
                Arc::new(Epoch(e.priority_accounts.iter().map(|(id,key)|(id.clone(),Account{key:key.clone(),data:Mutex::new(None)})).collect()))
            });
        }
        has_new
    }

    pub fn insert(&self, data:Vec<SignedValidator>) -> Result<Vec<SignedValidator>,Error> {
        let mut new = vec![];
        // TODO(gprusak): This can be parallelized.
        for d in data {
            match self.0.get(&d.epoch_id) {
                Some(e) => if e.insert(&d)? { new.push(d); }
                None => continue,
            }
        }
        Ok(new)
    }
}
