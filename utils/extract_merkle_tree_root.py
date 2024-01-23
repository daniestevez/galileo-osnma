#!/usr/bin/env python3

import sys
import xml.etree.ElementTree as ET


def main():
    tree = ET.parse(sys.argv[1])
    root = tree.getroot()
    for node in root.find('body').find('MerkleTree').findall('TreeNode'):
        if node.find('j').text == '4':
            print(node.find('x_ji').text)


if __name__ == '__main__':
    main()
