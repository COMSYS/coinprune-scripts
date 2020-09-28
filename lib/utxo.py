""" This file holds shared functionality regarding snapshot handling. """


import sys
import enum
import logging
from binascii import hexlify, unhexlify
from math import floor
from ecdsa.util import string_to_number

from btcpy.structs.script import Script

from lib import base, obfuscate

DEBUG = False

log = logging.getLogger('lib.utxo')
log.setLevel(level=logging.INFO if not DEBUG else logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(level=logging.INFO if not DEBUG else logging.DEBUG)
log.addHandler(ch)


# If STRICT is set to true, check expected compressed public keys for consistencs (First byte either 0x02 or 0x03)
# This check might be violated in case of inserted content, hence set this to False usually.
STRICT = False

SPECIAL_SCRIPTS = 6


class ScriptType(enum.IntEnum):
    P2PK_NONC = 0
    P2PK_COMP = 1
    P2PKH = 2
    P2SH = 3
    P2MS_1_1 = 4
    P2MS_1_2 = 5
    P2MS_1_3 = 6
    P2MS_2_2 = 7
    P2MS_2_3 = 8
    P2MS_3_3 = 9
    P2WPKH = 10
    P2WSH = 11

    P2PK_NONC_NONSTRICT = 12
    P2PK_COMP_NONSTRICT = 13

    CoinpruneP2PKH = 20
    CoinpruneP2SH = 21
    CoinpruneP2WPKH = 22
    CoinpruneP2WSH = 23

    OTHER_P2PKH_BUG = 250
    OTHER_OP2SWAP = 251
    OTHER_OP2OP3 = 252
    OTHER_INVALID_SEGWIT = 253
    OTHER_UNUSED_SEGWIT_VERSION = 254
    # OTHER_0 = 255
    OTHER = 256


scripttype_labels = {
    ScriptType.P2PK_NONC: ('p2pk_nonc', 'P2PK (uncompr.)'),
    ScriptType.P2PK_COMP: ('p2pk_comp', 'P2PK (compr.)'),
    ScriptType.P2PKH: ('p2pkh', 'P2PKH'),
    ScriptType.P2SH: ('p2sh', 'P2SH'),
    ScriptType.P2MS_1_1: ('p2ms_1_1', 'P2MS (1-1)'),
    ScriptType.P2MS_1_2: ('p2ms_1_2', 'P2MS (1-2)'),
    ScriptType.P2MS_1_3: ('p2ms_1_3', 'P2MS (1-3)'),
    ScriptType.P2MS_2_2: ('p2ms_2_2', 'P2MS (2-2)'),
    ScriptType.P2MS_2_3: ('p2ms_2_3', 'P2MS (2-3)'),
    ScriptType.P2MS_3_3: ('p2ms_3_3', 'P2MS (3-3)'),
    ScriptType.P2WPKH: ('p2wpkh', 'P2WPKH'),
    ScriptType.P2WSH: ('p2wsh', 'P2WSH'),

    ScriptType.P2PK_NONC_NONSTRICT: ('p2pk_nonc_nonstrict', 'P2PK (uncompr., non-strict)'),
    ScriptType.P2PK_COMP_NONSTRICT: ('p2pk_comp_nonstrict', 'P2PK (compr., nonstrict)'),

    ScriptType.CoinpruneP2PKH: ('coinprune_p2pkh', 'CoinPrune P2PKH'),
    ScriptType.CoinpruneP2SH: ('coinprune_p2sh', 'CoinPrune P2SH'),
    ScriptType.CoinpruneP2WPKH: ('coinprune_p2wpkh', 'CoinPrune P2WPKH'),
    ScriptType.CoinpruneP2WSH: ('coinprune_p2wsh', 'CoinPrune P2WSH'),

    ScriptType.OTHER_P2PKH_BUG: ('other_p2pkh_bug', 'other (P2PKH bug)'),
    ScriptType.OTHER_OP2SWAP: ('other_op2swap', 'other (OP_2SWAP)'),
    ScriptType.OTHER_OP2OP3: ('other_op2_op3', 'other (OP_2 OP_3)'),
    ScriptType.OTHER_INVALID_SEGWIT: ('other_invalid_segwit', 'other (invalid SegWit)'),
    ScriptType.OTHER_UNUSED_SEGWIT_VERSION: ('other_unused_segwit_version', 'other (unused SegWit version)'),
    ScriptType.OTHER: ('other', 'other'),
}


# Script Classification


def classify_uncompressed_script(script):
    # First, catch segwit cases
    if 4 <= len(script) <= 42 and 0x00 <= script[0] <= 0x0f and 2 <= script[1] <= 40:  # Some segwit case
        if script[0] == 0x00:
            if script[1] == 20 and len(script) == 22:
                return ScriptType.P2WPKH
            if script[1] == 32 and len(script) == 34:
                return ScriptType.P2WSH
            return ScriptType.OTHER_INVALID_SEGWIT
        else:
            return ScriptType.OTHER_UNUSED_SEGWIT_VERSION

    if len(script) >= 4 and script[0:2] == b'\x76\xa9' and script[-2:] == b'\x9d\xac':  # Potential P2PKH
        if len(script) == 25 and script[2] == 20:
            return ScriptType.P2PKH
        elif len(script) == 5 and script[2] == 0x00:
            return ScriptType.OTHER_P2PKH_BUG
        else:
            return ScriptType.OTHER
    if len(script) == 35 and script[0] == 33 and script[-1] == 0xac:  # P2PK compressed
        return ScriptType.P2PK_COMP if script[1] in [0x02, 0x03] else ScriptType.P2PK_COMP_NONSTRICT
    if len(script) == 67 and script[0] == 65 and script[-1] == 0xac:  # P2PK_NONC
        return ScriptType.P2PK_NONC if script[1] == 0x04 else ScriptType.P2PK_NONC_NONSTRICT
    if len(script) == 23 and script[0] == 0xa9 and script[1] == 20 and script[-1] == 0x87:
        return ScriptType.P2SH

    if script[-1] == 0xae:  # P2MS, check different cases
        # P2MS uses OP_1, OP_2, etc., which have opcodes 81, 82, ...
        m = script[0] - 80
        n = script[-2] - 80

        if n > 3 or m > n:
            return ScriptType.OTHER

        # Verify that no invalid (number of) public keys lie between m and n
        payload = script[1:-2]
        for _ in range(n):
            if payload[0] == 65:
                if len(payload) < 66:
                    return ScriptType.OTHER
                payload = payload[66:]
            elif payload[0] == 33:
                if len(payload) < 34 or (payload[1] not in [2, 3] if STRICT else False):
                    return ScriptType.OTHER
                payload = payload[34:]
        if len(payload) == 0:
            if n == 1:
                return ScriptType.P2MS_1_1
            if n == 2 and m == 1:
                return ScriptType.P2MS_1_2
            if n == 2 and m == 2:
                return ScriptType.P2MS_2_2
            if n == 3 and m == 1:
                return ScriptType.P2MS_1_3
            if n == 3 and m == 2:
                return ScriptType.P2MS_2_3
            if n == 3 and m == 3:
                return ScriptType.P2MS_3_3

    if script[:2] == b'\x52\x53':
        return ScriptType.OTHER_OP2OP3
    if script == b'\x73\x63\x72\x69\x70\x74':
        return ScriptType.OTHER_OP2SWAP
    return ScriptType.OTHER


def classify_compressed_script(script, is_obfuscated_snapshot=False):
    is_compressed = True
    res = None
    if script[0] == 0x00:  # P2PKH
        res = ScriptType.P2PKH
    elif script[0] == 0x01:  # P2SH
        res = ScriptType.P2SH
    elif script[0] in [0x02, 0x03]:  # P2PK compressed
        res = ScriptType.P2PK_COMP
    elif script[0] in [0x04, 0x05]:  # P2PK uncompressed
        res = ScriptType.P2PK_NONC
    else:  # No compressable script, fall back to uncompressed classification
        if is_obfuscated_snapshot:
            if script[0] == 0x06:
                res = ScriptType.CoinpruneP2PKH
            elif script[0] == 0x07:
                res = ScriptType.CoinpruneP2SH
            elif script[0] == 0x08:
                res = ScriptType.CoinpruneP2WPKH
            elif script[0] == 0x09:
                res = ScriptType.CoinpruneP2WSH
    if res is None:
        is_compressed = False
        len_script, offset = base.read_varint(script)
        res = classify_uncompressed_script(script[offset:(offset + len_script)])
        if res == ScriptType.OTHER:
            log.error(f'Detected OTHER script: {hexlify(script)} vs. {hexlify(script[offset:(offset + len_script)])}')
            log.error(f'Len script: {len_script}, Offset: {offset}')
    return res, is_compressed


def classify_script(script, compressed=False, is_obfuscated_snapshot=False):
    return classify_compressed_script(script, is_obfuscated_snapshot=is_obfuscated_snapshot) if compressed else (classify_uncompressed_script(script), False)


def get_script_payload_compressed(script, is_obfuscated_snapshot=False):
    _, is_compressed = classify_compressed_script(script, is_obfuscated_snapshot=is_obfuscated_snapshot)
    if is_compressed:
        return script[1:]
    else:
        len_script, offset = base.read_varint(script)
        return get_script_payload_uncompressed(script[offset:(offset + len_script)])


def get_script_payload_uncompressed(script):
    script_type = classify_uncompressed_script(script)

    if script_type == ScriptType.P2PKH:
        return script[3:23]
    elif script_type == ScriptType.P2SH:
        return script[2:22]
    elif script_type == ScriptType.P2PK_COMP:
        return script[1:34]
    elif script_type == ScriptType.P2PK_NONC:
        return script[1:66]
    elif script_type == ScriptType.P2WPKH:
        return script[1:21]
    elif script_type == ScriptType.P2WSH:
        return script[1:33]
    elif ScriptType.P2MS_1_1 <= script_type <= ScriptType.P2MS_3_3:
        n = base.read_charint(script[-2])
        offset = 1
        payloads = list()
        for _ in range(n):
            payload_length = base.read_charint(script[offset])
            new_offset = offset + 1 + payload_length
            payloads.append(script[(offset + 1):new_offset])
            offset = new_offset
        return payloads
    # TODO: Obfuscated values

    return None


# Script Compression and Decompression

def decompress_payload(case, payload, is_obfuscated_snapshot=False):
    # see bitcoin core compressor.cpp:96
    if case == 0:  # P2PKH
        script = b'\x76\xa9' + bytes([20]) + payload + b'\x9d\xac'
    elif case == 1:  # P2SH
        script = b'\xa9' + bytes([20]) + payload + b'\x87'
    elif case == 2 or case == 3:  # P2PK compressed pubkey
        script = bytes([33]) + bytes([case]) + payload + b'\xac'
    elif case == 4 or case == 5:  # P2PK uncompressed pubkey
        pubkey = b'\x00' * 65  # FIXME: The technicalities of this case are out of scope for our prototype
        script = bytes([65]) + pubkey + b'\xac'
    elif is_obfuscated_snapshot and case == 6:
        script = b'\x76\xa9\xaa' + bytes([32]) + payload + b'\x9d\xac'
    elif is_obfuscated_snapshot and case == 7:
        script = b'\xa9\xaa' + bytes([32]) + payload + b'\x87'
    elif is_obfuscated_snapshot and case == 8:
        script = b'\x00\xb3\xaa' + bytes([32]) + payload
    elif is_obfuscated_snapshot and case == 9:
        script = b'\x00\xb4\xaa' + bytes([32]) + payload

    return script


def read_script(data):
    size, _ = base.read_varint(data)
    if size < SPECIAL_SCRIPTS:
        size = 20 if size in [0, 1] else 32
    else:
        size -= SPECIAL_SCRIPTS

    return data[:(size + 1)]


def read_script_file(file_handler, is_obfuscated_snapshot=False):
    size = base.read_varint_file(file_handler)
    if size < SPECIAL_SCRIPTS:
        actual_size = 20 if size in [0, 1] else 32
    elif is_obfuscated_snapshot and size < SPECIAL_SCRIPTS + 4:
        actual_size = 32
    else:
        actual_size = size - (SPECIAL_SCRIPTS + (4 if is_obfuscated_snapshot else 0))
    return base.write_varint(size) + file_handler.read(actual_size)


def decompress_script(data, is_obfuscated_snapshot=False):  # see bitcoin core compressor.h:63
    size, offset = base.read_varint(data)
    data = data[offset:]
    if size < SPECIAL_SCRIPTS:
        case = size
        size = 20 if size in [0, 1] else 32  # see bitcoin core compressor.cpp:87
        script_payload = data[:size]
        return decompress_payload(case, script_payload, is_obfuscated_snapshot=is_obfuscated_snapshot)

    size -= SPECIAL_SCRIPTS
    script = data[:size]

    return script


def decompress_script_file(file_handler, is_obfuscated_snapshot=False):  # see bitcoin core compressor.h:63
    size = base.read_varint_file(file_handler)
    if size < SPECIAL_SCRIPTS:
        case = size
        size = 20 if size in [0, 1] else 32  # see bitcoin core compressor.cpp:87
        script_payload = file_handler.read(size)
        return decompress_payload(case, script_payload, is_obfuscated_snapshot=is_obfuscated_snapshot)
    elif is_obfuscated_snapshot and size < SPECIAL_SCRIPTS + 4:
        case = size
        size = 32
        script_payload = file_handler.read(size)
        return decompress_payload(case, script_payload, is_obfuscated_snapshot=is_obfuscated_snapshot)

    size -= SPECIAL_SCRIPTS
    script = file_handler.read(size)

    return script


def compress_payload(case, payload, obfuscate=True):
    assert case < SPECIAL_SCRIPTS

    # Obfuscate value and change case accordingly, if requested
    new_case = case + (SPECIAL_SCRIPTS if obfuscate else 0)
    new_payload = obfuscate.obfuscate_payload_simple(payload) if obfuscate else payload

    return bytes([new_case]) + new_payload


def compress_script(script, obfuscate=True):
    script_type, is_compressed = classify_script(script, compressed=False)
    if is_compressed:
        return script

    if script_type == ScriptType.P2PKH:
        payload = get_script_payload_uncompressed(script)
        return compress_payload(0x00, payload, obfuscate)
    elif script_type == ScriptType.P2SH:
        payload = get_script_payload_uncompressed(script)
        return compress_payload(0x01, payload, obfuscate)
    elif script_type == ScriptType.P2PK_COMP:
        payload = get_script_payload_uncompressed(script)
        return compress_payload(base.read_charint(payload[0]), payload, obfuscate)
    elif script_type == ScriptType.P2PK_NONC:
        payload = get_script_payload_uncompressed(script)
        enc_x, y = payload[1:17], string_to_number(payload[17:33])
        case = 0x04 + (0x01 if y % 2 else 0x00)
        return compress_payload(case, enc_x, obfuscate)

    return base.write_varint(len(script)) + script


def compress_script_file(file_handler, script):
    file_handler.write(compress_script(script))


cases = dict()


def add_case(script_type):
    res = False
    if script_type not in cases.keys():
        cases[script_type] = 0
        res = True
    cases[script_type] += 1
    return res


def obfuscate_compressed_script(script):
    script_type, is_compressed = classify_script(script, compressed=True)

    # Only compressible types
    if script_type in [ScriptType.P2PKH, ScriptType.P2SH, ScriptType.P2WPKH, ScriptType.P2WSH]:
        payload = get_script_payload_compressed(script)
        payload = obfuscate.obfuscate_payload_simple(payload)
        if script_type == ScriptType.P2PKH:
            case = SPECIAL_SCRIPTS + 0x00
        elif script_type == ScriptType.P2SH:
            case = SPECIAL_SCRIPTS + 0x01
        elif script_type == ScriptType.P2WPKH:
            case = SPECIAL_SCRIPTS + 0x02
        elif script_type == ScriptType.P2WSH:
            case = SPECIAL_SCRIPTS + 0x03

        res = bytes([case]) + payload
        obfuscated = True
        compressed = True
    elif script_type in [ScriptType.P2PK_NONC, ScriptType.P2PK_COMP] and is_compressed:
        res = script
        obfuscated = False
        compressed = True
    else:
        res = script
        res, offset = base.read_varint(script)
        res = script[offset:]
        res = base.write_varint(SPECIAL_SCRIPTS + 4 + len(res)) + res
        obfuscated = False
        compressed = is_compressed

    add_case(script_type)

    return res, obfuscated, compressed


def obfuscate_compressed_script_file(file_handler, script):
    script_new, _, _ = obfuscate_compressed_script(script)
    file_handler.write(script_new)


# TxOut Value Handling


# See bitcoin core compressor.cpp:169
def decompress_value(v):
    if v == 0:
        return 0
    v -= 1
    e = v % 10
    v = int(floor(v / 10))
    n = 0
    if e < 9:
        d = (v % 9) + 1
        v = int(floor(v / 9))
        n = v * 10 + d
    else:
        n = v + 1
    while e > 0:
        n *= 10
        e -= 1
    return n


# See src/compressor.cpp:150
def compress_value(v):
    if v == 0:
        return 0
    e = 0
    while ((v % 10) == 0) and e < 9:
        v /= 10
        e += 1
    if e < 9:
        d = v % 10
        assert 1 <= d <= 9
        v /= 10
        return 1 + (((v * 9) + d - 1) * 10) + e
    else:
        return 1 + ((v - 1) * 10) + 9


# Full TxOuts

def read_txout(data, decompress=False):
    value_compressed, offset = base.read_varint(data)
    value = decompress_value(value_compressed)
    script = decompress_script(data[offset:]) if decompress else read_script(data[offset:])

    return (script, value)


def read_txout_file(file_handler, decompress=False, is_obfuscated_snapshot=False):
    value = decompress_value(base.read_varint_file(file_handler))
    script = decompress_script_file(file_handler, is_obfuscated_snapshot=is_obfuscated_snapshot) if decompress else read_script_file(file_handler, is_obfuscated_snapshot=is_obfuscated_snapshot)

    return (script, value)


def write_txout(txout, compressed=True, obfuscate=True):
    script, value = txout
    value_compressed = compress_value(value)
    script_compressed = script if compressed else compress_script(script, obfuscate=obfuscate)
    return base.write_varint(value_compressed) + script_compressed


# UTXO Coin

def read_coin(data, decompress=False):
    code, offset = base.read_varint(data)
    block_height = code >> 1
    is_coinbase = code & 1
    txout = read_txout(data[offset:], decompress)

    return (block_height, txout, is_coinbase)


def read_coin_file(file_handler, decompress=False, is_obfuscated_snapshot=False):
    code = base.read_varint_file(file_handler)
    block_height = code >> 1
    is_coinbase = code & 1
    txout = read_txout_file(file_handler, decompress, is_obfuscated_snapshot=is_obfuscated_snapshot)

    return (block_height, txout, is_coinbase)


def write_coin(coin):
    block_height, txout, is_coinbase = coin
    code = (block_height << 1) | is_coinbase

    return base.write_varint(code) + write_txout(txout)


def write_coin_file(file_handler, coin):
    file_handler.write(write_coin(coin))


# UTXO Outpoint

def read_outpoint(data):
    res_hash = hexlify(data[:32][::-1])
    res_n = base.read_int(data[32:(32 + 4)])
    return res_hash, res_n


def read_outpoint_file(file_handler):
    data = file_handler.read(32 + 4)
    return read_outpoint(data)


def write_outpoint(outpoint):
    outpoint_hash, outpoint_n = outpoint
    serialized_hash = unhexlify(outpoint_hash)[::-1]
    serialized_n = base.write_int(outpoint_n)
    return serialized_hash + serialized_n


def write_outpoint_file(file_handler, outpoint):
    file_handler.write(write_outpoint(outpoint))


# UTXO Histogram

def get_utxo_histogram(utxos, is_obfuscated_snapshot=False):
    histogram = dict()
    other = list()
    for i, utxo in enumerate(utxos):
        outpoint, coin = utxo[0], utxo[1]
        script = coin[1][0]

        script_type, _ = classify_script(script, compressed=True, is_obfuscated_snapshot=is_obfuscated_snapshot)
        if script_type not in histogram.keys():
            histogram[script_type] = 0
        histogram[script_type] += 1

        if script_type >= 200:
            other.append((outpoint[0], outpoint[1], scripttype_labels[script_type][0], script))

    return histogram, other


def print_utxo_histogram_header(file_out=None):
    if file_out is None:
        file_out = sys.stdout
    csv_header = 'chunk_height;chunk_offset'
    for k in ScriptType._member_names_:
        csv_header += f';{scripttype_labels[ScriptType[k]][0]}'
    print(f'{csv_header}', file=file_out)


def print_utxo_other_header(file_out=None):
    print('chunk_height;chunk_offset;txid;tx_index;script_type;script', file=file_out)


def print_utxo_histogram(histogram, chunk_height, chunk_offset, file_out=None, machine=False):
    if file_out is None:
        file_out = sys.stdout
    if machine:
        csv_line = f'{chunk_height};{chunk_offset}'
        for k in ScriptType._member_names_:
            v = histogram[ScriptType[k]] if ScriptType[k] in histogram.keys() else 0
            csv_line += f';{v}'
        print(csv_line, file=file_out)
    else:
        for k in histogram.keys():
            print(f'{scripttype_labels[k][1]}: {histogram[k]}', file=file_out)


def print_other_utxos(other, chunk_height, chunk_offset, file_out=None, machine=False):
    if file_out is None:
        file_out = sys.stderr
    if not machine:
        print(f'Chunk height: {chunk_height}', file=file_out)
        print(f'Chunk offset: {chunk_offset}', file=file_out)
        print()
    for o in other:
        if machine:
            other_str = f'{chunk_height};{chunk_offset};{o[0].decode()};{o[1]};{o[2]};{Script.unhexlify(hexlify(o[3])).decompile()}'
        else:
            other_str = f'({o[0].decode()}, {o[1]}): {Script.unhexlify(hexlify(o[3])).decompile()} ({o[2]})'
        print(other_str, file=file_out)
