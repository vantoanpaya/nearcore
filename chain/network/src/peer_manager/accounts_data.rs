
impl PeerManagerActor {
    fn handle_sync_accounts_data(&self, data:Vec<SignedValidator>) {
        let view_client = self.view_client_addr.clone();
        let accounts_data = self.accounts_data.clone();
        self.accounts_data_threadpool.spawn(async move{
            let info = match view_client.send(NetworkViewClientMessages::GetChainInfo).await.unwrap() {
                NetworkViewClientResponses::GetChainInfo(it) => it,
                _ => panic!("expected GetChainInfo"),
            };
            if accounts_data.lock().set_epochs(vec![&*info.this_epoch,&*info.next_epoch]) {
                self.broadcast_message(
                    self.network_metrics.clone(),
                    &self.connected_peers,
                    SendMessage {
                        message: PeerMessage::SyncAccountDataRequest,
                        context: Span::current().context(),
                    },
                );
            }
            match accounts_data.lock().insert(validators) {
                Ok(new_data) => {
                    self.broadcast_message(
                        self.network_metrics.clone(),
                        &self.connected_peers,
                        SendMessage {
                            message: PeerMessage::SyncAccountData(new_data),
                            context: Span::current().context(),
                        },
                    );
                }
                Err(_err) => {
                    // TODO: ban peer
                    // TODO: in fact, with the current implementation, even if some new
                    // data has been accepted, it won't be broadcasted and may cause state
                    // inconsistency between connected peers.
                }
            }
        });
    }
}
