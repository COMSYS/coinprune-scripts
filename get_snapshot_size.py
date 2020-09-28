#!/usr/bin/env python3
""" This file determines the size of a given snapshot. """

import os
import sys
import argparse
import logging
import glob


DEBUG = False


log = logging.getLogger('parse_chunk_file')
log.setLevel(level=logging.INFO if not DEBUG else logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(level=logging.INFO if not DEBUG else logging.DEBUG)
log.addHandler(ch)


if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('folder', type=str, help='Folder holding all snapshot chunks')
    argparser.add_argument('snapshot_height', type=int, help='Block height of the snapshot to extract')
    argparser.add_argument('--opreturn', action='store_true', help='Application data storage instead of snapshot')
    args = argparser.parse_args()

    filesize_total = 0

    suffix = 'opreturns' if args.opreturn else 'state'
    snapshot_filename = f'{args.folder}/{args.snapshot_height:010d}.{suffix}'
    chunk_filenames = glob.glob(f'{args.folder}/chunks/{args.snapshot_height:010d}_**.chunk')
    filenames = [snapshot_filename] + chunk_filenames

    for filename in filenames:
        filesize_total += os.path.getsize(filename)

    print(f'{filesize_total}')
