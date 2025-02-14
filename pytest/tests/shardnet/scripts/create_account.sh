#!/bin/bash
set -x

account_id=$(grep account_id /home/ubuntu/.near/shardnet/validator_key.json | awk -F'"' '{print $4}')
mkdir -p /home/ubuntu/.near-credentials/shardnet/
echo "{\"account_id\":\"$account_id\",\"public_key\":\"$1\",\"private_key\":\"$2\"}" > /home/ubuntu/.near-credentials/shardnet/near.json
pk=$(grep public_key /home/ubuntu/.near/shardnet/validator_key.json | awk -F'"' '{print $4}')
cp /home/ubuntu/.near/shardnet/validator_key.json /home/ubuntu/.near-credentials/shardnet/$account_id.json
NEAR_ENV=shardnet near --nodeUrl=http://127.0.0.1:3030 create-account $account_id --masterAccount near --initialBalance 1000000 --publicKey $pk
