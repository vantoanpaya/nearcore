use crate::accounts_data::*;
use crate::testonly::{make_rng,Rng};
use crate::network_protocol::{AccountData,SignedAccountData};
use crate::network_protocol::testonly as data;
use near_crypto::{SecretKey,InMemorySigner};
use near_primitives::types::{AccountId,EpochId};
use near_network_primitives::types::{EpochInfo};
use near_network_primitives::time;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default)]
struct Signers{
    keys : HashMap<(EpochId,AccountId),SecretKey>,
}

impl Signers {
    fn key(&mut self, rng :&mut Rng, epoch_id: &EpochId, account_id:&AccountId) -> &SecretKey {
        self.keys.entry((epoch_id.clone(),account_id.clone()))
            .or_insert_with(||data::make_secret_key(rng))
    }

    fn make_epoch(&mut self, rng: &mut Rng, account_ids: &[&AccountId]) -> EpochInfo {
        let epoch_id = data::make_epoch_id(rng);
        EpochInfo {
            id: epoch_id.clone(),
            priority_accounts: account_ids.iter().map(|aid|((*aid).clone(),self.key(rng,&epoch_id,&aid).public_key())).collect(),
        }
    }

    fn make_account_data(&mut self, rng: &mut Rng, epoch_id: &EpochId, account_id: &AccountId, timestamp: time::Utc) -> SignedAccountData {
        let signer = InMemorySigner::from_secret_key(
            account_id.clone(),
            self.key(rng,epoch_id,account_id).clone(),
        );
        AccountData {
            peers: (0..3).map(|_|{
                let ip = data::make_ipv6(rng);
                data::make_peer_addr(rng,ip)
            }).collect(),
            account_id: account_id.clone(),
            epoch_id: epoch_id.clone(),
            timestamp,
        }.sign(&signer).unwrap()
    }
}

#[tokio::test]
async fn test_accounts_data() {
    let mut rng = make_rng(2947294234);
    let rng = &mut rng;
    let clock = time::FakeClock::default();
    let now = clock.now_utc();

    let accounts : Vec<_> = (0..4).map(|_|data::make_account_id(rng)).collect();
    let mut signers = Signers::default();
    let e0 = signers.make_epoch(rng,&[&accounts[0],&accounts[1],&accounts[2]]);
    let e1 = signers.make_epoch(rng,&[&accounts[0],&accounts[3]]);
    let e2 = signers.make_epoch(rng,&[&accounts[1],&accounts[2]]);
    
    let ad = Arc::new(AccountsData::new());
    assert_eq!(ad.dump(),vec![]);  // initially empty
    ad.set_epochs(vec![&e0,&e1]);
    assert_eq!(ad.dump(),vec![]);  // empty after initial set_epoch.
    
    // initial insert
    let e0a0 = signers.make_account_data(rng,&e0.id,&accounts[0],now);
    let e0a1 = signers.make_account_data(rng,&e0.id,&accounts[1],now);
    let res = ad.clone().insert(vec![e0a0.clone(),e0a1.clone()]).await;
    // TODO: output requires normalization.
    assert_eq!((vec![e0a0.clone(),e0a1.clone()],None),res);
    assert_eq!(vec![e0a0.clone(),e0a1.clone()],ad.dump());

    // entries of various types
    let e1a0 = signers.make_account_data(rng,&e1.id,&accounts[0],now);
    let e0a0new = signers.make_account_data(rng,&e0.id,&accounts[0],now+time::Duration::seconds(1));
    let e0a1old = signers.make_account_data(rng,&e0.id,&accounts[0],now-time::Duration::seconds(1));
    let e2a1 = signers.make_account_data(rng,&e2.id,&accounts[1],now);
    let e1a1 = signers.make_account_data(rng,&e1.id,&accounts[2],now);
    let res = ad.clone().insert(vec![
        e1a0.clone(), // initial value => insert
        e0a0new.clone(), // with newer timestamp => insert,
        e0a1old.clone(), // with older timestamp => filter,
        e2a1.clone(), // from inactive epoch => filter,
        e1a1.clone(), // account not in the given active epoch => filter,
    ]).await;
    assert_eq!((vec![e1a0.clone(),e0a0new.clone()],None),res);
    assert_eq!(vec![e0a0new.clone(),e0a1.clone(),e1a0.clone()],ad.dump());

    // set_epoch again. Entries from inactive epochs should be dropped.
    ad.set_epochs(vec![&e0,&e2]);
    assert_eq!(vec![e0a0new.clone(),e0a1.clone()],ad.dump());
    // insert some entries again. 
    let e0a2 = signers.make_account_data(rng,&e0.id,&accounts[2],now);
    let e1a3 = signers.make_account_data(rng,&e1.id,&accounts[3],now);
    let res = ad.clone().insert(vec![
        e0a2.clone(), // e0 is still active => insert,
        e1a3.clone(), // e1 is not active any more => filter,
        e2a1.clone(), // e2 has become active => insert,
    ]).await;
    assert_eq!((vec![e0a2.clone(),e2a1.clone()],None),res);
    assert_eq!(vec![e0a0new.clone(),e0a1.clone(),e0a2.clone(),e2a1.clone()],ad.dump());

    // TODO
    // too large payload => DataTooLarge
    // some invalid signature => partial update is allowed
    // concurrent update => higher wins, lower is filtered out
}
