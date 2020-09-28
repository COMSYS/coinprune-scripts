""" This file holds chunk-related functionality. """


import hashlib
from binascii import hexlify

from lib import base


MAX_SIZE_CHUNK = 10**6


# Chunk hash

def get_chunk_hash(chunk):
    res = chunk
    res = hashlib.sha256(res).digest()
    res = hashlib.sha256(res).digest()
    res = hexlify(res).decode()
    return res


def get_chunk_hash_file(file_handler):
    chunk = file_handler.read()
    return get_chunk_hash(chunk)


# Chunk height

def read_chunk_height_file(file_handler):
    return base.read_int_file(file_handler, offset=0)


def write_chunk_height_file(file_handler, snapshot_height):
    base.write_int_file(file_handler, snapshot_height)


# Chunk offset

def read_chunk_offset_file(file_handler):
    return base.read_int_file(file_handler, offset=4)


def write_chunk_offset_file(file_handler, offset):
    base.write_int_file(file_handler, offset)


# Chunk length


def check_chunk_length(chunk_size_old, num_entries_old, candidate_entry):
    # Header consists of two 4-byte ints and the compact int denoting the number of utxos
    return 4 + 4 + len(base.write_compact_int(num_entries_old + 1)) + chunk_size_old + len(candidate_entry)


# Number of UTXOs in chunk


def read_num_utxos_file(file_handler):
    number_utxos, new_offset = base.read_compact_int_file(file_handler, offset=8)
    return number_utxos, new_offset


def write_utxos_file(file_handler, utxos):
    base.write_compact_int_file(file_handler, len(utxos))
    utxos_serialized = b''.join(utxos)
    file_handler.write(utxos_serialized)


def write_opreturns_file(file_handler, opreturns):
    base.write_compact_int_file(file_handler, len(opreturns))
    opreturns_serialized = b''.join(opreturns)
    file_handler.write(opreturns_serialized)
