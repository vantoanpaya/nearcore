use std::collections::HashMap;

struct Epoch {
    keys : Arc<HashMap<AccountId,PublicKey>>,
    data : HashMap<AccountId,SignedValidator>,
}

pub(crate) struct ValidatorsData {
    epochs : HashMap<EpochId,Epoch>
}

pub enum Error {
    InvalidSignature,
}

impl ValidatorsData {
    pub fn update_epochs(&mut self, epochs:Vec<EpochInfo>) -> Vec<EpochId> {
        self.epochs.retain(|id,_|epochs.iter().any(|e|e.id==id));
        for e in epochs {
            self.epochs.entry(e.id).or_insert(Epoch{keys:e.priority_accounts,data:HashMap::new});
        }
    }

    pub async fn update_data(&mut self, data:Vec<SignedValidator>) -> Result<Vec<SignedValidator>,Error> {
        let new = vec![];
        // TODO(gprusak): This can be parallelized.
        for d in data {
            // Check if we care about (d.epoch_id,d.account_id).
            let epoch := match self.epochs.get(d.epoch_id) {
                Some(e) => e,
                None => continue,
            }
            let key := match e.keys.get(d.account_id) {
                Some(key) => key,
                None => continue,
            };
            // Skip if we already have a newer data for (d.epoch_id,d.account_id).
            match e.data.get(d.account_id) {
                Some(old) if old.timestamp>=d.timestamp => continue,
                _ => {}
            }
            // Verify the signature. 
            if !v.signature.verify(&v.payload,key) {
                return Err(Error::InvalidSignature);
            }
            new.push(d.clone());
            e.data.insert(d.account_id,d);
        }
        Ok(new)
    }
}
