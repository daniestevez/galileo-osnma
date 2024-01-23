#!/bin/bash

set -e

if [[ $# -ne 1 ]]; then
    echo "Test vector directory must be indicated as parameter" >&2
    exit 2
fi

export RUST_LOG=info
ORIG_CWD="$(pwd)"
TEST_VECTOR_DIR="$(realpath $1)"
cd "$(dirname "$0")"

echo "Building software"

cargo build --release
cd ../galmon-osnma
cargo build --release
cd -

CONVERT=./target/release/osnma-test-vectors-to-galmon
GALMON_OSNMA=../galmon-osnma/target/release/galmon-osnma
GET_MERKLE=./extract_merkle_tree_root.py

PUBKEY=/tmp/pubkey.pem

echo "Test vector: Configuration 1"

openssl x509 \
        -in "${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_1/PublicKey/OSNMA_PublicKey_20230803105952_newPKID_1.crt" \
        -noout -pubkey > $PUBKEY
PKID=1
MERKLE="$($GET_MERKLE ${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_1/MerkleTree/OSNMA_MerkleTree_20230803105953_newPKID_1.xml)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/configuration_1/16_AUG_2023_GST_05_00_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Configuration 2"

openssl x509 \
        -in "${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_2/PublicKey/OSNMA_PublicKey_20230720113300_newPKID_2.crt" \
        -noout -pubkey > $PUBKEY
PKID=2
MERKLE="$($GET_MERKLE ${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_2/MerkleTree/OSNMA_MerkleTree_20230720113300_newPKID_2.xml)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/configuration_2/27_JUL_2023_GST_00_00_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

cd $ORIG_CWD
