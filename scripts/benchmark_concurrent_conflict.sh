#!/usr/bin/env bash
# Real concurrency/MVCC-conflict test against the live local Fabric
# test-network: fires K simultaneous RecordTest invokes at the SAME
# componentID (a real write-write race on one ledger key), so Fabric's
# MVCC validation should accept at most one and reject the rest with a
# real conflict, not a scripted/simulated one.
set -uo pipefail

CID="${1:?usage: benchmark_concurrent_conflict.sh <componentID> <K>}"
K="${2:?usage: benchmark_concurrent_conflict.sh <componentID> <K>}"

cd "/Users/chenyuling/Desktop/論文/fabric-samples/test-network"
export PATH=${PWD}/../bin:/opt/homebrew/bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config
export CORE_PEER_TLS_ENABLED=true
export ORDERER_CA=${PWD}/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
P1=organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
P2=organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

EVDIR="/Users/chenyuling/Desktop/論文/automotive-component-traceability-fabric/evidence"
mkdir -p "$EVDIR/concurrent_raw"
rm -f "$EVDIR/concurrent_raw"/attempt_*.log

echo "=== Concurrent conflict test: componentID=${CID}, K=${K} concurrent RecordTest calls, $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee "$EVDIR/concurrent_conflict_summary.txt"

for ((i=1; i<=K; i++)); do
  H=$(printf 'concurrent QC report attempt %s' "$i" | shasum -a 256 | awk '{print $1}')
  (
    T0=$(date +%s.%N)
    OUT=$(peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
      -C mychannel -n component-traceability --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 \
      --waitForEvent --waitForEventTimeout 30s \
      -c "{\"function\":\"RecordTest\",\"Args\":[\"$CID\",\"$H\",\"Org2MSP\"]}" 2>&1)
    T1=$(date +%s.%N)
    DUR=$(python3 -c "print(round($T1-$T0,3))")
    {
      echo "attempt=$i duration=${DUR}s"
      echo "$OUT"
    } > "$EVDIR/concurrent_raw/attempt_${i}.log"
  ) &
done
wait

SUCCESS=0
FAIL=0
for ((i=1; i<=K; i++)); do
  f="$EVDIR/concurrent_raw/attempt_${i}.log"
  if grep -q "committed with status (VALID)" "$f"; then
    SUCCESS=$((SUCCESS+1))
    echo "attempt $i: SUCCESS" | tee -a "$EVDIR/concurrent_conflict_summary.txt"
  else
    FAIL=$((FAIL+1))
    REASON=$(grep -iE "Error|ENDORSEMENT|MVCC|conflict|status" "$f" | head -1)
    echo "attempt $i: FAILED - $REASON" | tee -a "$EVDIR/concurrent_conflict_summary.txt"
  fi
done

echo "" | tee -a "$EVDIR/concurrent_conflict_summary.txt"
echo "Result: ${SUCCESS} succeeded, ${FAIL} failed, out of ${K} concurrent attempts on the same key (${CID})." | tee -a "$EVDIR/concurrent_conflict_summary.txt"

# Final ledger state, to confirm exactly one write actually took effect
echo "Final ledger state:" | tee -a "$EVDIR/concurrent_conflict_summary.txt"
peer chaincode query -C mychannel -n component-traceability -c "{\"function\":\"GetComponent\",\"Args\":[\"$CID\"]}" 2>&1 | tee -a "$EVDIR/concurrent_conflict_summary.txt"
