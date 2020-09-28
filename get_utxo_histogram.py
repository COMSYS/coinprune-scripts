#!/usr/bin/env python3
""" This script creates histogram of which txout types are present in a snapshot.
    Namely, this script creates two CSV files in the given --target-folder:

    1. Histogram CSV file containing the counts for each txout type that occurred.
    2. Another CSV file, which contains the output scripts of all txouts classified as "others". """

import argparse
import glob

import progressbar

from parse_chunk_file import parse_chunk_file
from lib import utxo as utxo_handler


if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('folder', type=str, help='Folder holding all snapshot chunks')
    argparser.add_argument('snapshot_height', type=int, help='Block height of the snapshot to extract')
    argparser.add_argument('--target-folder', type=str, help='Target folder for output', default='.')
    argparser.add_argument('--target-prefix', type=str, help='Prefix of output file', default='utxo_hist_')
    argparser.add_argument('--obfuscated-snapshot', action='store_true', help='Use if you are analysing an obfuscated snapshot')
    args = argparser.parse_args()

    f_histogram = open(f'{args.target_folder}/{args.target_prefix}{args.snapshot_height:010d}_histogram.csv', 'w')
    f_other = open(f'{args.target_folder}/{args.target_prefix}{args.snapshot_height:010d}_others.csv', 'w')

    utxo_handler.print_utxo_histogram_header(f_histogram)
    utxo_handler.print_utxo_other_header(f_other)
    filenames = glob.glob(f'{args.folder}/chunks/{args.snapshot_height:010d}_**.chunk')
    bar = progressbar.ProgressBar(max_value=len(filenames), redirect_stdout=True)
    for i, chunk_filename in enumerate(sorted(filenames)):
        chunk_height, chunk_offset, chunk_hash, utxos = parse_chunk_file(chunk_filename, is_obfuscated_snapshot=args.obfuscated_snapshot)
        histogram, other = utxo_handler.get_utxo_histogram(utxos, is_obfuscated_snapshot=args.obfuscated_snapshot)
        utxo_handler.print_utxo_histogram(histogram, chunk_height, chunk_offset, f_histogram, machine=True)
        utxo_handler.print_other_utxos(other, chunk_height, chunk_offset, f_other, machine=True)
        bar.update(i)

    f_histogram.close()
    f_other.close()
