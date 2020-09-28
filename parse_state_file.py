#!/usr/bin/env python3
""" Parse the metafile of a given snapshot. """

import argparse
import binascii

from lib import base


def read_snapshot_height_file(file_handler):
    return base.read_int_file(file_handler)


def write_snapshot_height_file(file_handler, snapshot_height):
    base.write_int_file(file_handler, snapshot_height)


def read_block_hash_file(file_handler):
    return file_handler.read(32)[::-1]


def write_block_hash_file(file_handler, block_hash_bin):
    file_handler.write(block_hash_bin[::-1])


def read_num_chunks_file(file_handler):
    return base.read_int_file(file_handler)


def write_num_chunks_file(file_handler, num_chunks):
    base.write_int_file(file_handler, num_chunks)


def read_snapshot_file(file_handler):
    snapshot_height = read_snapshot_height_file(file_handler)
    block_hash = read_block_hash_file(file_handler)
    num_chunks = read_num_chunks_file(file_handler)

    return (snapshot_height, block_hash, num_chunks)


def write_snapshot_file(file_handler, snapshot_height, block_hash, num_chunks):
    write_snapshot_height_file(file_handler, snapshot_height)
    write_block_hash_file(file_handler, block_hash)
    write_num_chunks_file(file_handler, num_chunks)


if __name__ == '__main__':

    argparser = argparse.ArgumentParser()
    argparser.add_argument('filename', type=str, help='Name of the state file to load')
    args = argparser.parse_args()

    with open(args.filename, 'rb') as f:
        state_height = read_snapshot_height_file(f)
        state_latest_block_hash = binascii.hexlify(read_block_hash_file(f)).decode()
        state_num_chunks = read_num_chunks_file(f)

    print('State file name: {}'.format(args.filename))
    print('')
    print('State block height: {}'.format(state_height))
    print('Latest block hash: {}'.format(state_latest_block_hash))
    print('Number chunks: {}'.format(state_num_chunks))
