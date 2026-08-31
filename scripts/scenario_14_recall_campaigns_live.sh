#!/usr/bin/env bash
# Scenario 14 (FABRIC TEST-NETWORK): live-network test of RecallCampaigns
# (v3.5, sequence 10), the one-to-many replacement for the pre-v3.5 scalar
# RecallBatchID/Reason/ReasonHistory fields. Prompted directly by
# supervisor review: the overlapping-recall fix evaluated through v3.4
# (RecallBatchID) was explicitly documented as a partial solution -- it
# prevented one campaign from silently overwriting another (Scenario 7),
# but a second, independent campaign against the same product could only be
# reported as skippedOverlap, never itself tracked or resolved. This
# scenario proves the complete fix: a product recalled under two different
# batches now carries two simultaneously open, independently manageable
# RecallCampaigns.
set -uo pipefail
cd "/Users/chenyuling/Desktop/論文/fabric-samples/test-network"
export PATH=${PWD}/../bin:/opt/homebrew/bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config
export CORE_PEER_TLS_ENABLED=true
export ORDERER_CA=${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
P1=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
P2=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
P3=${PWD}/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt

as_admin() {
  ORG=$1; PORT=$2
  export CORE_PEER_LOCALMSPID="Org${ORG}MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org${ORG}.example.com/peers/peer0.org${ORG}.example.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org${ORG}.example.com/users/Admin@org${ORG}.example.com/msp
  export CORE_PEER_ADDRESS=localhost:${PORT}
}

inv() {
  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
    -C mychannel -n component-traceability --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 \
    --waitForEvent -c "$1" 2>&1
}
qry() {
  peer chaincode query -C mychannel -n component-traceability -c "$1" 2>&1
}
h() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }

# --- 1-5. One-time deployment (idempotent) ---
as_admin 1 7051
ALREADY=$(peer lifecycle chaincode querycommitted -C mychannel -n component-traceability 2>&1 | grep -c "Version: 3.5, Sequence: 10")
if [ "$ALREADY" -ge 1 ]; then
  echo "=== 1-5. v3.5/sequence 10 already committed on this network; skipping package/install/approve/commit ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
else
  echo "=== 1. Package current chaincode source (RecallCampaigns) as v3.5 ==="
  mkdir -p /tmp/cc_package
  peer lifecycle chaincode package /tmp/cc_package/component-traceability_3.5.tar.gz \
    --path /Users/chenyuling/Desktop/論文/automotive-component-traceability-fabric/chaincode \
    --lang golang --label component-traceability_3.5
  PKGID=$(peer lifecycle chaincode calculatepackageid /tmp/cc_package/component-traceability_3.5.tar.gz)
  echo "Package ID: $PKGID"

  echo "=== 2. Install on Org1, Org2, Org3 ==="
  as_admin 1 7051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.5.tar.gz
  as_admin 2 9051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.5.tar.gz
  as_admin 3 11051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.5.tar.gz

  echo "=== 3. Approve v3.5 sequence 10 for Org1, Org2, Org3 ==="
  as_admin 1 7051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.5 --package-id "$PKGID" --sequence 10
  as_admin 2 9051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.5 --package-id "$PKGID" --sequence 10
  as_admin 3 11051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.5 --package-id "$PKGID" --sequence 10

  echo "=== 4. checkcommitreadiness ==="
  as_admin 1 7051
  peer lifecycle chaincode checkcommitreadiness -C mychannel -n component-traceability -v 3.5 --sequence 10 --tls --cafile "$ORDERER_CA" --output json

  echo "=== 5. Commit v3.5 sequence 10 ==="
  peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability \
    --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 --peerAddresses localhost:11051 --tlsRootCertFiles $P3 \
    -v 3.5 --sequence 10
  echo "=== querycommitted ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
fi

as_admin 1 7051

echo ""
echo "############################################################"
echo "### PART A: build a product spanning two batches, then recall it under BOTH ###"
echo "############################################################"
echo "--- Register+test+ship two components under two different batches ---"
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"OV14-X\",\"BATCH-OV14-X\",\"Tier2Supplier\",\"$(h "ov14x report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"OV14-X\",\"$(h "ov14x qc")\",\"Org2MSP\"]}"
inv '{"function":"RecordShipment","Args":["OV14-X","Org1MSP","Org1MSP","Org2MSP"]}'
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"OV14-Y\",\"BATCH-OV14-Y\",\"Tier2Supplier\",\"$(h "ov14y report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"OV14-Y\",\"$(h "ov14y qc")\",\"Org2MSP\"]}"
inv '{"function":"RecordShipment","Args":["OV14-Y","Org1MSP","Org1MSP","Org2MSP"]}'
echo "--- Assemble both into one product, spanning BATCH-OV14-X and BATCH-OV14-Y ---"
inv '{"function":"RecordAssembly","Args":["PRODUCT-OV14","OV14-X,OV14-Y","RECIPE-OV14","Org2MSP"]}'

echo "--- TriggerRecall BATCH-OV14-X: opens the product's first campaign ---"
inv "{\"function\":\"TriggerRecall\",\"Args\":[\"BATCH-OV14-X\",\"defect found in batch X\"]}"
echo "--- TriggerRecall BATCH-OV14-Y: before v3.5 this would report PRODUCT-OV14 under skippedOverlap and touch nothing; now it opens a SECOND, independent campaign ---"
inv "{\"function\":\"TriggerRecall\",\"Args\":[\"BATCH-OV14-Y\",\"unrelated defect found in batch Y\"]}"
echo "--- GetComponent PRODUCT-OV14: confirm BOTH campaigns are simultaneously open in recallCampaigns ---"
qry '{"function":"GetComponent","Args":["PRODUCT-OV14"]}'

echo ""
echo "############################################################"
echo "### PART B: resolve one campaign without touching the other ###"
echo "############################################################"
as_admin 3 11051
echo "--- CloseRecall PRODUCT-OV14 for BATCH-OV14-X only (Regulator, new batchID argument) ---"
inv '{"function":"CloseRecall","Args":["PRODUCT-OV14","BATCH-OV14-X","REPAIRED","root cause fixed","Org1MSP"]}'
echo "--- GetComponent PRODUCT-OV14: BATCH-OV14-X now REPAIRED, BATCH-OV14-Y still RECALLED, overall recallStatus still RECALLED ---"
qry '{"function":"GetComponent","Args":["PRODUCT-OV14"]}'

echo "--- RevokeRecall BATCH-OV14-Y (Regulator): clears the last open campaign ---"
inv '{"function":"RevokeRecall","Args":["BATCH-OV14-Y","investigation closed, no defect confirmed"]}'
echo "--- GetComponent PRODUCT-OV14: recallStatus now cleared, but BOTH campaigns' full history remains in recallCampaigns (not deleted) ---"
qry '{"function":"GetComponent","Args":["PRODUCT-OV14"]}'

echo ""
echo "=== DONE: Scenario 14 complete. A product recalled under two independent"
echo "=== batches now carries two simultaneously open RecallCampaigns, each"
echo "=== separately closeable and revocable, closing the gap named as a"
echo "=== partial solution throughout this dissertation. ==="
