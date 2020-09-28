#!/usr/bin/env python3
""" This file parses a histogram CSV file generated via get_utxo_histogram.py. """

import sys

import argparse
import pandas as pd

if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('folder', type=str, help='Folder holding all snapshot chunks')
    argparser.add_argument('snapshot_height', type=int, help='Block height of the snapshot to extract')
    argparser.add_argument('--prefix', type=str, help='Prefix of output file', default='utxo_hist_')
    args = argparser.parse_args()

    with open(f'{args.folder}/{args.prefix}{args.snapshot_height:010d}_histogram.csv', 'r') as f_histogram:
        data = pd.read_csv(f_histogram, sep=';')

    res = dict()
    res['chunk_height'] = args.snapshot_height
    for column in data:
        if column in ['chunk_height', 'chunk_offset']:
            continue
        res[column] = data[column].sum()

    data_out = pd.DataFrame(res, index=['absolute']).drop('chunk_height', axis=1).transpose()
    total_utxos = data_out.sum(axis=0)[0]
    print(str(total_utxos))
    data_out['relative'] = (100. * data_out['absolute']) / (1. * total_utxos)
    print(str(data_out))
