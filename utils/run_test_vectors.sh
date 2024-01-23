#!/bin/bash

set -e

if [[ $# -ne 1 ]]; then
    echo "Test vector directory must be indicated as parameter" >&2
    exit 2
fi

export RUST_LOG=${RUST_LOG:=warn,galmon_osnma=info}
ORIG_CWD="$(pwd)"
TEST_VECTOR_DIR=$1
GALILEO_OSNMA_DIR="$(dirname "$0")/../"

echo "Building software"

cd $GALILEO_OSNMA_DIR/osnma-test-vectors-to-galmon
cargo build --release
cd $ORIG_CWD
cd $GALILEO_OSNMA_DIR/galmon-osnma
cargo build --release
cd $ORIG_CWD

CONVERT=$GALILEO_OSNMA_DIR/osnma-test-vectors-to-galmon/target/release/osnma-test-vectors-to-galmon
GALMON_OSNMA=$GALILEO_OSNMA_DIR/galmon-osnma/target/release/galmon-osnma
GET_MERKLE=$GALILEO_OSNMA_DIR/utils/extract_merkle_tree_root.py
GET_PUBKEY=$GALILEO_OSNMA_DIR/utils/extract_public_key.py

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

echo "Test vector: Chain Renewal (all steps chained)"

openssl x509 \
        -in "${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_2/PublicKey/OSNMA_PublicKey_20231007041500_PKID_7.crt" \
        -noout -pubkey > $PUBKEY
PKID=7

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/eoc_step1/06_OCT_2023_GST_16_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/eoc_step2/06_OCT_2023_GST_18_30_01.csv" ; }  | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true


echo "Test vector: Chain Renewal (step 1 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/eoc_step1/06_OCT_2023_GST_16_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Chain Renewal (step 2 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/eoc_step2/06_OCT_2023_GST_18_30_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Chain Revocation (all steps chained)"

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step1/06_OCT_2023_GST_21_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step2/06_OCT_2023_GST_23_30_01.csv" ; \
  echo "Step 3" >&2 ;
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step3/07_OCT_2023_GST_00_30_01.csv" ; }  | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Chain Revocation (step 1 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step1/06_OCT_2023_GST_21_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Chain Revocation (step 2 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step2/06_OCT_2023_GST_23_30_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Chain Revocation (step 3 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step3/07_OCT_2023_GST_00_30_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Public Key Renewal (all steps chained)"

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step1/07_OCT_2023_GST_02_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step2/07_OCT_2023_GST_03_45_01.csv" ; \
  echo "Step 3" >&2 ;
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step3/07_OCT_2023_GST_04_45_01.csv" ; }  | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Public Key Renewal (step 1 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step1/07_OCT_2023_GST_02_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Public Key Renewal (step 2 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step2/07_OCT_2023_GST_03_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Public Key Renewal (step 3 only, starting with PKID 7)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step3/07_OCT_2023_GST_04_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Public Key Renewal (step 3 only, starting with PKID 8)"

openssl x509 \
        -in "${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_2/PublicKey/OSNMA_PublicKey_20231007081500_PKID_8.crt" \
        -noout -pubkey > $PUBKEY
PKID=8

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step3/07_OCT_2023_GST_04_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Public Key Revocation (all steps chained)"

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step1/07_OCT_2023_GST_07_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step2/07_OCT_2023_GST_09_30_01.csv" ; \
  echo "Step 3" >&2 ;
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step3/07_OCT_2023_GST_10_30_01.csv" ; }  | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Public Key Revocation (step 1 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step1/07_OCT_2023_GST_07_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Public Key Revocation (step 2 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step2/07_OCT_2023_GST_09_30_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Public Key Revocation (step 3 only, starting with PKID 8)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step3/07_OCT_2023_GST_10_30_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: Public Key Revocation (step 3 only, starting with PKID 9)"

PUBKEY_P521="$($GET_PUBKEY ${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_2/PublicKey/OSNMA_PublicKey_20231007141500_PKID_9.xml)"
PKID=9

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step3/07_OCT_2023_GST_10_30_01.csv" | \
    $GALMON_OSNMA --pubkey-p521 $PUBKEY_P521 --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: New Merkle Tree (all steps chained)"

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step1/07_OCT_2023_GST_12_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step2/07_OCT_2023_GST_13_45_01.csv" ; \
  echo "Step 3" >&2 ;
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step3/07_OCT_2023_GST_14_45_01.csv" ; }  | \
    $GALMON_OSNMA --pubkey-p521 $PUBKEY_P521 --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: New Merkle Tree (step 1 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step1/07_OCT_2023_GST_12_45_01.csv" | \
    $GALMON_OSNMA --pubkey-p521 $PUBKEY_P521 --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: New Merkle Tree (step 2 only, starting with Merkle tree 2 and PKID 9)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step2/07_OCT_2023_GST_13_45_01.csv" | \
    $GALMON_OSNMA --pubkey-p521 $PUBKEY_P521 --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: New Merkle Tree (step 3 only, starting with Merkle tree 2 and PKID 9)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step3/07_OCT_2023_GST_14_45_01.csv" | \
    $GALMON_OSNMA --pubkey-p521 $PUBKEY_P521 --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: New Merkle Tree (step 2 only, starting with Merkle tree 3 and PKID 1)"

openssl x509 \
        -in "${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_3/PublicKey/OSNMA_PublicKey_20231008111500_PKID_1.crt" \
        -noout -pubkey > $PUBKEY
PKID=1
MERKLE="$($GET_MERKLE ${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_3/MerkleTree/OSNMA_MerkleTree_20231007201500_PKID_1.xml)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step2/07_OCT_2023_GST_13_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: New Merkle Tree (step 3 only, starting with Merkle tree 3 and PKID 1)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step3/07_OCT_2023_GST_14_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: OSNMA Alert Message (all steps chained)"

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/oam_step1/07_OCT_2023_GST_18_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/oam_step2/07_OCT_2023_GST_19_45_01.csv" ; } | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: OSNMA Alert Message (step 1 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/oam_step1/07_OCT_2023_GST_18_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo "Test vector: OSNMA Alert Message (step 2 only)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/oam_step2/07_OCT_2023_GST_19_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true
