#!/usr/bin/env python3

import argparse
import sys

import ecdsa


def parse_args():
    parser = argparse.ArgumentParser(
        prog='sec1_to_pem.py',
        description='Converts a SEC1 encoded public key in hex to PEM format')
    parser.add_argument('--curve', default='NIST256p')
    parser.add_argument('sec1_hex')
    return parser.parse_args()


def main():
    args = parse_args()
    curve = getattr(ecdsa, args.curve)
    sec1 = bytes.fromhex(args.sec1_hex)
    vk = ecdsa.VerifyingKey.from_string(sec1, curve=curve)
    print(str(vk.to_pem(), encoding='ascii'), end='')


if __name__ == '__main__':
    main()
