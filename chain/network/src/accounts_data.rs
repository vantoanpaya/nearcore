//! Cache of AccountsData for a small number of epochs. (probably just current and next epoch).
//! Assumptions:
//! - verifying signatures is expensive, we need a dedicated threadpool for handling that.
//!
//!TODO(gprusak): it would be nice to have a benchmark for that
//! - a bad peer may attack by sending a lot of invalid signatures
//! - we can afford validating all valid signatures (for the given epochs) that we have never seen before.
//! - we can afford validating a few invalid signatures per PeerMessage.
//!
//! Strategy:
//! - handling of SyncAccountDataResponses should be throttled by PeerActor/PeerManagerActor.
//! - synchronously select interesting AccountsData (i.e. those with never timestamp than any
//!   previously seen for the given (account_id,epoch_id) pair.
//! - asynchronously verify signatures, until an invalid signature is encountered.
//! - if any signature is invalid, drop validation of the remaining signature and ban the peer
//! - all valid signatures verified, so far should be recorded (otherwise we are open to an attack
//!     - a bad peer may spam us with <N valid AccountData> + <1 invalid AccountData>
//!     - we would validate everything every time, realizing that the last one is invalid, then
//!       discarding the progress
//!     - banning a peer wouldn't help since peers are anonymous, so a single attacker can act as a
//!       lot of peers
use std::collections::HashMap;
use std::sync::Arc;
use near_crypto::{PublicKey};
use near_primitives::types::{AccountId,EpochId};
use crate::network_protocol::SignedAccountData;
use crate::network_protocol;
use near_network_primitives::types::EpochInfo;
use parking_lot::{RwLock};
use near_network_primitives::time;

struct Account {
    key: PublicKey,
    data: Option<SignedAccountData>,
}

impl Account {
    fn is_new(&self, t:time::Utc) -> bool {
        match &self.data {
            Some(old) if old.timestamp>=t => false,
            _ => true,
        }
    }
}

struct Epoch(HashMap<AccountId,Account>);

impl Epoch {
    fn new(keys:&HashMap<AccountId,PublicKey>) -> Self {
        Self(keys.iter().map(|(id,key)|(id.clone(),Account{
            key:key.clone(), data: None,
        })).collect())
    }
}

pub(crate) enum Error {
    InvalidSignature,
    DataTooLarge,
}

pub struct Epochs(HashMap<EpochId,Epoch>);

impl Epochs {
    fn with_key(&self, d:SignedAccountData) -> Option<(SignedAccountData,PublicKey)> {
        let a = self.0.get(&d.epoch_id)?.0.get(&d.account_id)?;
        if !a.is_new(d.timestamp) {
            return None;
        }
        Some((d,a.key.clone()))
    }

    fn try_insert(&mut self, d:SignedAccountData) -> Option<SignedAccountData> {
        let mut a = self.0.get_mut(&d.epoch_id)?.0.get_mut(&d.account_id)?;
        if !a.is_new(d.timestamp) {
            return None;
        }
        a.data = Some(d.clone());
        Some(d)
    }
}

pub(crate) struct AccountsData{
    epochs: RwLock<Epochs>,
    runtime: tokio::runtime::Runtime,
}

impl AccountsData {
    pub fn new() -> Arc<Self> {
        Arc::new(Self{
            epochs: RwLock::new(Epochs(HashMap::new())),
            runtime: tokio::runtime::Runtime::new().unwrap(),
        })
    }

    /// Sets new_epochs as active and copies over the keys 
    /// for accounts which were not active before.
    /// The set of accounts per epoch is expected to be deterministic,
    /// So it is not possible to update the set of accounts for an already
    /// active epoch - such an update will be ignored silently.
    /// This code is more general than needed: active epochs are expected
    /// to be just {this_epoch,next_epoch} and set_epochs should be called
    /// every time chain advances to the next epoch. It can be called
    /// more often - it will be a (cheap) noop in this case.
    pub fn set_epochs(&self, new_epochs:Vec<&EpochInfo>) -> bool {
        let mut epochs = self.epochs.write();
        epochs.0.retain(|id,_|new_epochs.iter().any(|e|&e.id==id));
        let mut has_new = false;
        for e in new_epochs {
            epochs.0.entry(e.id.clone()).or_insert_with(||{
                has_new = true;
                Epoch::new(&e.priority_accounts)
            });
        }
        has_new
    }

    /// Verifies the signatures and inserts verified data to the cache.
    /// Returns the data inserted and optionally a verification error.
    /// WriteLock is acquired only for the final update (after verification),
    /// so it is possible to execute dump() in parallel.
    pub async fn insert(self:Arc<Self>, data:Vec<SignedAccountData>) -> (Vec<SignedAccountData>,Option<Error>) {
        // Filter out non-interesting data, so that we never check signatures for valid non-interesting data.
        // Bad peers may force us to check signatures for fake data anyway, but we will ban them after first invalid signature.
        let epochs = self.epochs.read();
        for d in &data {
            if d.payload().len()>network_protocol::MAX_ACCOUNT_DATA_SIZE_BYTES {
                return Err(Error::DataTooLarge)
            }
        }
        let data_and_keys : Vec<_> = data.into_iter().filter_map(|d|epochs.with_key(d)).collect();
        drop(epochs);

        // We validate signatures synchronously for now, but in a dedicated thread.
        // To validate signatures in parallel, we should have a way to stop validation at the first invalid one.
        let (data,err) = self.runtime.spawn(async move {
            let mut data = vec![];
            for (d,key) in data_and_keys {
                if !d.payload().verify(&key) {
                    return (data,Some(Error::InvalidSignature));
                }
                data.push(d);
            }
            (data,None)
        }).await.unwrap();

        // Insert the verified data, even if an error has been encountered.
        let mut epochs = self.epochs.write();
        Ok(data.into_iter().filter_map(|d|epochs.try_insert(d)).collect(),err)
    }

    /// Copies and returns all the AccountData in the cache.
    pub fn dump(&self) -> Vec<SignedAccountData> {
        self.epochs.read().0.values().map(|e|&e.0).flatten().filter_map(|(_,a)|a.data.clone()).collect()
    }
}
