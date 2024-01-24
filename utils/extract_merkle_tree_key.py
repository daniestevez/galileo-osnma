#!/usr/bin/env python3

import argparse
import sys
import xml.etree.ElementTree as ET


def parse_args():
    parser = argparse.ArgumentParser(
        prog='extract_merkle_tree_key.py',
        description=('Extracts the ECDSA public key from '
                     'an XML file for a Merkle tree'))
    parser.add_argument('input_file')
    return parser.parse_args()


def main():
    args = parse_args()
    tree = ET.parse(args.input_file)
    root = tree.getroot()
    pk = root.find('body').find('MerkleTree').find('PublicKey')
    print(pk.find('point').text)


if __name__ == '__main__':
    main()
