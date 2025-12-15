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

cd $GALILEO_OSNMA_DIR
cargo build --release
cd $ORIG_CWD

CONVERT=$GALILEO_OSNMA_DIR/target/release/osnma-test-vectors-to-galmon
GALMON_OSNMA=$GALILEO_OSNMA_DIR/target/release/galmon-osnma
GET_MERKLE=$GALILEO_OSNMA_DIR/utils/extract_merkle_tree_root.py
GET_PUBKEY=$GALILEO_OSNMA_DIR/utils/extract_public_key.py
GET_PUBKEY_FROM_MERKLE=$GALILEO_OSNMA_DIR/utils/extract_merkle_tree_key.py
SEC1_TO_PEM=$GALILEO_OSNMA_DIR/utils/sec1_to_pem.py

PUBKEY=/tmp/pubkey.pem

echo ""
echo "Test vector: Configuration 1"
echo "----------------------------"
echo ""
echo "There should be no errors in this test, and there should be successful "
echo "authentications of navigation data."
echo ""

openssl x509 \
        -in "${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_1/PublicKey/OSNMA_PublicKey_20230803105952_newPKID_1.crt" \
        -noout -pubkey > $PUBKEY
PKID=1
MERKLE="$($GET_MERKLE ${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_1/MerkleTree/OSNMA_MerkleTree_20230803105953_newPKID_1.xml)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/configuration_1/16_AUG_2023_GST_05_00_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Configuration 2"
echo "----------------------------"
echo ""
echo "There should be no errors in this test, and there should be successful"
echo "authentications of navigation data."
echo ""

openssl x509 \
        -in "${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_2/PublicKey/OSNMA_PublicKey_20230720113300_newPKID_2.crt" \
        -noout -pubkey > $PUBKEY
PKID=2
MERKLE="$($GET_MERKLE ${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_2/MerkleTree/OSNMA_MerkleTree_20230720113300_newPKID_2.xml)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/configuration_2/27_JUL_2023_GST_00_00_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Chain Renewal (all steps chained)"
echo "----------------------------------------------"
echo ""
echo "Some TESLA key validation errors are expected in step 2. These happen because"
echo "in the subframe when the chain change happens, the MACKs for some satellites are"
echo "completed and processed before the DSM is completed by collecting DSM blocks"
echo "from multiple satellites in that subframe. Obtaining the DSM-KROOT is required"
echo "to validate the new CID."
echo ""

openssl x509 \
        -in "${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_2/PublicKey/OSNMA_PublicKey_20231007041500_PKID_7.crt" \
        -noout -pubkey > $PUBKEY
PKID=7

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/eoc_step1/06_OCT_2023_GST_16_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/eoc_step2/06_OCT_2023_GST_18_30_01.csv" ; }  | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Chain Renewal (step 1 only)"
echo "----------------------------------------"
echo ""
echo "No errors are expected in this test."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/eoc_step1/06_OCT_2023_GST_16_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Chain Renewal (step 2 only)"
echo "----------------------------------------"
echo ""
echo "Some TESLA key validation errors are expected in this step. These happen because"
echo "in the subframe when the chain change happens, the MACKs for some satellites are"
echo "completed and processed before the DSM is completed by collecting DSM blocks"
echo "from multiple satellites in that subframe. Obtaining the DSM-KROOT is required"
echo "to validate the new CID."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/eoc_step2/06_OCT_2023_GST_18_30_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Chain Revocation (all steps chained)"
echo "-------------------------------------------------"
echo ""
echo "No errors are expected in this test."
echo ""

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step1/06_OCT_2023_GST_21_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step2/06_OCT_2023_GST_23_30_01.csv" ; \
  echo "Step 3" >&2 ;
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step3/07_OCT_2023_GST_00_30_01.csv" ; }  | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Chain Revocation (step 1 only)"
echo "-------------------------------------------"
echo ""
echo "No errors are expected in this test."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step1/06_OCT_2023_GST_21_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Chain Revocation (step 2 only)"
echo "-------------------------------------------"
echo ""
echo "No errors are expected in this test."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step2/06_OCT_2023_GST_23_30_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Chain Revocation (step 3 only)"
echo "-------------------------------------------"
echo ""
echo "No errors are expected in this step."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/crev_step3/07_OCT_2023_GST_00_30_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Public Key Renewal (all steps chained)"
echo "---------------------------------------------------"
echo "No errors should happen in this test."
echo ""

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step1/07_OCT_2023_GST_02_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step2/07_OCT_2023_GST_03_45_01.csv" ; \
  echo "Step 3" >&2 ;
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step3/07_OCT_2023_GST_04_45_01.csv" ; }  | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Public Key Renewal (step 1 only)"
echo "---------------------------------------------"
echo "No errors should happen in this test."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step1/07_OCT_2023_GST_02_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Public Key Renewal (step 2 only)"
echo "---------------------------------------------"
echo "No errors should happen in this test."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step2/07_OCT_2023_GST_03_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Public Key Renewal (step 3 only, starting with PKID 7)"
echo "-------------------------------------------------------------------"
echo "No errors should happen in this test."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step3/07_OCT_2023_GST_04_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Public Key Renewal (step 3 only, starting with PKID 8)"
echo "-------------------------------------------------------------------"
echo "No errors should happen in this test."
echo ""

openssl x509 \
        -in "${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_2/PublicKey/OSNMA_PublicKey_20231007081500_PKID_8.crt" \
        -noout -pubkey > $PUBKEY
PKID=8

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/npk_step3/07_OCT_2023_GST_04_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Public Key Revocation (all steps chained)"
echo "------------------------------------------------------"
echo ""
echo "No errors are expected in this test."
echo ""

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step1/07_OCT_2023_GST_07_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step2/07_OCT_2023_GST_09_30_01.csv" ; \
  echo "Step 3" >&2 ;
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step3/07_OCT_2023_GST_10_30_01.csv" ; }  | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Public Key Revocation (step 1 only)"
echo "------------------------------------------------"
echo ""
echo "No errors are expected in this test."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step1/07_OCT_2023_GST_07_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Public Key Revocation (step 2 only)"
echo "------------------------------------------------"
echo ""
echo "No errors are expected in this test."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step2/07_OCT_2023_GST_09_30_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Public Key Revocation (step 3 only, starting with PKID 8)"
echo "----------------------------------------------------------------------"
echo ""
echo "No errors are expected in this test."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step3/07_OCT_2023_GST_10_30_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: Public Key Revocation (step 3 only, starting with PKID 9)"
echo "----------------------------------------------------------------------"
echo ""
echo "No errors are expected in this test."
echo ""

PUBKEY_P521="$($GET_PUBKEY ${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_2/PublicKey/OSNMA_PublicKey_20231007141500_PKID_9.xml)"
PKID=9

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/pkrev_step3/07_OCT_2023_GST_10_30_01.csv" | \
    $GALMON_OSNMA --pubkey-p521 $PUBKEY_P521 --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: New Merkle Tree (all steps chained, starting with Merkle tree 2 and PKID 9)"
echo "----------------------------------------------------------------------------------------"
echo ""
echo "After the CPKS changes to New Merkle Tree, public key verification errors"
echo "will appear, because the DSM-PKR now refers to a Merkle tree different from"
echo "the one that is loaded into the receiver. Additionally, DSM-KROOT verification".
echo "errors will appear in after Step 2 begins, since the DSM-KROOT starts to be"
echo "signed with the key from the new Merkle tree. However, navigation data authentication"
echo "should continue successfully throughout the test, since the TESLA chain is not"
echo "changed."
echo ""

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step1/07_OCT_2023_GST_12_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step2/07_OCT_2023_GST_13_45_01.csv" ; \
  echo "Step 3" >&2 ;
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step3/07_OCT_2023_GST_14_45_01.csv" ; }  | \
    $GALMON_OSNMA --pubkey-p521 $PUBKEY_P521 --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: New Merkle Tree (step 1 only)"
echo "------------------------------------------"
echo ""
echo "After the CPKS changes to New Merkle Tree, public key verification errors"
echo "will appear, because the DSM-PKR now refers to a Merkle tree different from"
echo "the one that is loaded into the receiver."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step1/07_OCT_2023_GST_12_45_01.csv" | \
    $GALMON_OSNMA --pubkey-p521 $PUBKEY_P521 --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: New Merkle Tree (step 2 only, starting with Merkle tree 2 and PKID 9)"
echo "----------------------------------------------------------------------------------"
echo ""
echo "In this test there will be errors regarding public key verification and KROOT"
echo "verification, since both use a Merkle tree which is different from the one"
echo "loaded in the receiver. However, navigation data authentication should continue"
echo "successfully throughout the test, since some of the DSM-KROOTs are signed with"
echo "the key from the old Merkle tree and the TESLA chain is not changed."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step2/07_OCT_2023_GST_13_45_01.csv" | \
    $GALMON_OSNMA --pubkey-p521 $PUBKEY_P521 --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: New Merkle Tree (step 3 only, starting with Merkle tree 2 and PKID 9)"
echo "----------------------------------------------------------------------------------"
echo ""
echo "In this test there will be errors regarding public key verification and KROOT"
echo "verification, since both use a Merkle tree which is different from the one"
echo "loaded in the receiver. Additionally, no navigation data authentication should"
echo "happen, since all the DSM-KROOTs transmitted in this step are signed with the"
echo "key from the new Merkle tree".
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step3/07_OCT_2023_GST_14_45_01.csv" | \
    $GALMON_OSNMA --pubkey-p521 $PUBKEY_P521 --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: New Merkle Tree (step 2 only, starting with Merkle tree 3 and PKID 1)"
echo "----------------------------------------------------------------------------------"
echo ""
echo "In this test there will be some errors regarding KROOT verification, since some"
echo "of the DSM-KROOTs are signed with the public key from the old Merkle tree."
echo "Navigation data authentication should be successful, since there are also DSM-KROOTs"
echo "signed with the public key from the new Merkle tree."
echo ""

openssl x509 \
        -in "${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_3/PublicKey/OSNMA_PublicKey_20231007201500_PKID_1.crt" \
        -noout -pubkey > $PUBKEY
PKID=1
MERKLE="$($GET_MERKLE ${TEST_VECTOR_DIR}/cryptographic_material/Merkle_tree_3/MerkleTree/OSNMA_MerkleTree_20231007201500_PKID_1.xml)"

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step2/07_OCT_2023_GST_13_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: New Merkle Tree (step 3 only, starting with Merkle tree 3 and PKID 1)"
echo "----------------------------------------------------------------------------------"
echo ""
echo "No errors are expected in this test, since there is nothing in the signal-in-space"
echo "that refers to the old Merkle tree."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/nmt_step3/07_OCT_2023_GST_14_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: OSNMA Alert Message (all steps chained)"
echo "----------------------------------------------------"
echo ""
echo "Navigation data authentication should be successful until the reception of the"
echo "Alert Message. At this point all cryptographic material is deleted and"
echo "verification errors for the KROOT and the Alert Message appear."
echo ""

{ echo "Step 1" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/oam_step1/07_OCT_2023_GST_18_45_01.csv" ; \
  echo "Step 2" >&2 ; \
  $CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/oam_step2/07_OCT_2023_GST_19_45_01.csv" ; } | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: OSNMA Alert Message (step 1 only)"
echo "----------------------------------------------"
echo ""
echo "Navigation data authentication should be successful until the reception of the"
echo "Alert Message. At this point all cryptographic material is deleted and"
echo "verification errors for the KROOT and the Alert Message will appear."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/oam_step1/07_OCT_2023_GST_18_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true

echo ""
echo "Test vector: OSNMA Alert Message (step 2 only)"
echo "----------------------------------------------"
echo ""
echo "No navigation data authentication should happen, since the NMA status is always"
echo "set to don't use. When the Alert Message is received, all cryptographic material"
echo "is deleted and verification errors for the KROOT and the Alert Message appear."
echo ""

$CONVERT "${TEST_VECTOR_DIR}/osnma_test_vectors/oam_step2/07_OCT_2023_GST_19_45_01.csv" | \
    $GALMON_OSNMA --pubkey $PUBKEY --pkid $PKID --merkle-root $MERKLE || true
