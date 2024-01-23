#!/usr/bin/env python3

import argparse
import sys
import xml.etree.ElementTree as ET


def parse_args():
    parser = argparse.ArgumentParser(
        prog='extract_merkle_tree_root.py',
        description='Extracts the Merkle tree root from an XML file')
    parser.add_argument('input_file')
    return parser.parse_args()


def main():
    args = parse_args()
    tree = ET.parse(args.input_file)
    root = tree.getroot()
    for node in root.find('body').find('MerkleTree').findall('TreeNode'):
        if node.find('j').text == '4':
            print(node.find('x_ji').text)


if __name__ == '__main__':
    main()
