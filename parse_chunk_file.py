#!/usr/bin/env python3
""" Parse individual outpoints of a single chunk file. """

import sys
import argparse
from binascii import hexlify
import logging


from lib import chunk
from lib import utxo as utxo_handler

DEBUG = False

log = logging.getLogger('parse_chunk_file')
log.setLevel(level=logging.INFO if not DEBUG else logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(level=logging.INFO if not DEBUG else logging.DEBUG)
log.addHandler(ch)


def parse_chunk_file(filename, is_obfuscated_snapshot=False):
    log.debug('Parsing a single chunk file.')
    chunk_utxos = list()
    with open(filename, 'rb') as f:
        chunk_height = chunk.read_chunk_height_file(f)
        chunk_offset = chunk.read_chunk_offset_file(f)
        chunk_num_utxos, offset = chunk.read_num_utxos_file(f)
        log.debug(f'Number of UTXOs: {chunk_num_utxos}, File position starting UTXOs: {offset}, is obfuscated snapshot: {is_obfuscated_snapshot}')
        f.seek(offset)
        for i in range(chunk_num_utxos):
            outpoint = utxo_handler.read_outpoint_file(f)
            coin = utxo_handler.read_coin_file(f, is_obfuscated_snapshot=is_obfuscated_snapshot)
            chunk_utxos.append((outpoint, coin))
    return chunk_height, chunk_offset, chunk_num_utxos, chunk_utxos


if __name__ == '__main__':

    argparser = argparse.ArgumentParser()
    argparser.add_argument('filename', type=str, help='Name of the state chunk file to load')
    argparser.add_argument('--histogram', action='store_true', help='Create a histogram of script types in this chunk?')
    argparser.add_argument('--machine', action='store_true', help='Create machine-readable output?')
    argparser.add_argument('--obfuscated-snapshot', action='store_true', help='Decode obfuscated chunk file')
    args = argparser.parse_args()

    with open(args.filename, 'rb') as f:
        chunk_hash = chunk.get_chunk_hash_file(f)

    chunk_height, chunk_offset, chunk_num_utxos, utxos = parse_chunk_file(args.filename, args.obfuscated_snapshot)

    if not args.machine:
        print(f'Chunk file name: {args.filename}')
        print('')
        print(f'State block height: {chunk_height}')
        print(f'Chunk offset in state: {chunk_offset}')
        print(f'Number UTXos in chunk: {chunk_num_utxos}')
        print(f'Chunk hash: {chunk_hash}')

    if args.histogram:
        histogram, other = utxo_handler.get_utxo_histogram(utxos)
        utxo_handler.print_utxo_histogram(histogram, chunk_height, chunk_offset, sys.stdout, args.machine)
        utxo_handler.print_other_utxos(other, chunk_height, chunk_offset, sys.stderr, args.machine)

    else:
        print('\n\nUTXOs in chunk (outpoint, coin) = (txid, index (block_height, tx_out = (script, value), is_coinbase))):\n')
        for (ctr, utxo) in enumerate(utxos[:10]):
            outpoint, coin = utxo[0], utxo[1]
            print('{:6d}: {}, {} ({}, {}, {})'.format(
                ctr,
                str(outpoint[0]),
                str(outpoint[1]),
                str(coin[0]),
                str(coin[1]),
                str(coin[2]),
            ))
