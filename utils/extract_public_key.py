#!/usr/bin/env python3

import argparse
import sys
import xml.etree.ElementTree as ET


def parse_args():
    parser = argparse.ArgumentParser(
        prog='extract_public_key.py',
        description='Extracts the Public key from an XML file')
    parser.add_argument('input_file')
    return parser.parse_args()


def main():
    args = parse_args()
    tree = ET.parse(args.input_file)
    root = tree.getroot()
    print(root.find('body').find('PublicKey').find('point').text)


if __name__ == '__main__':
    main()
