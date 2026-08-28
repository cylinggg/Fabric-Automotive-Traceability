#!/usr/bin/env bash
# Measures the real byte size of TriggerRecall's RecallAlert chaincode
# event by registering a small fresh batch, triggering a recall, fetching
# the committed block that contains it, and decoding the event payload
# out of the block's protobuf structure with configtxlator.
#
# This directly answers the "does the recall event payload grow with
# batch size, and by how much" question: rather than assuming a trend,
# it captures one real measurement (N=20) from the live network. That
# measurement is then cross-checked in Python against the exact JSON
# encoding the chaincode itself performs (json.Marshal of the same map,
# with Go's alphabetical key ordering and no extra whitespace) -- if the
# reconstruction does not match the live-captured bytes exactly, the
# script fails loudly rather than silently reporting an estimate.
set -euo pipefail
cd "/Users/chenyuling/Desktop/論文/fabric-samples/test-network"
export PATH=${PWD}/../bin:/opt/homebrew/bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config
export CORE_PEER_TLS_ENABLED=true
export ORDERER_CA=${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051
P1=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
P2=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt

N=20
BATCH="BATCH-PAYLOAD-TEST"
echo "=== Registering $N fresh components for payload measurement ==="
for i in $(seq 1 $N); do
  CID="PAYLOAD-TEST-$i"
  H=$(printf 'payload test report %s' "$i" | shasum -a 256 | awk '{print $1}')
  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability \
    --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 \
    --waitForEvent \
    -c "{\"function\":\"RegisterComponent\",\"Args\":[\"$CID\",\"$BATCH\",\"Tier2Supplier\",\"$H\",\"Org1MSP,Org2MSP\"]}"
done

echo "=== TriggerRecall ==="
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability \
  --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 \
  --waitForEvent \
  -c "{\"function\":\"TriggerRecall\",\"Args\":[\"$BATCH\",\"payload measurement test\"]}"

echo "=== Fetch newest block and decode the RecallAlert event ==="
peer channel fetch newest /tmp/payload_test_block.pb -c mychannel \
  -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA"
configtxlator proto_decode --type=common.Block --input=/tmp/payload_test_block.pb --output=/tmp/payload_test_block.json

python3 - <<'PYEOF'
import json, base64
with open('/tmp/payload_test_block.json') as f:
    block = json.load(f)
data = block['data']['data'][0]
events = data['payload']['data']['actions'][0]['payload']['action']['proposal_response_payload']['extension']['events']
ep = events['payload']
decoded = base64.b64decode(ep)
print("event_name:", events['event_name'])
print("tx_id:", events['tx_id'])
print("live_captured_bytes:", len(decoded))
print(decoded.decode('utf-8'))

# Cross-check: reconstruct the same structure independently and confirm
# byte-for-byte match before trusting the projection to other N.
payload = json.loads(decoded)
n = payload['affectedCount']
tokens = sorted([f'PAYLOAD-TEST-{i}' for i in range(1, n+1)])
reconstructed = json.dumps({
    'affectedCount': n,
    'batchId': payload['batchId'],
    'notifiedOwners': payload['notifiedOwners'],
    'recalledTokens': tokens,
    'skippedOverlap': [],
    'txId': payload['txId'],
}, separators=(',', ':'))
assert reconstructed == decoded.decode('utf-8'), "reconstruction mismatch -- do not trust projected sizes"
print("reconstruction_matches_live_capture: True")
PYEOF
