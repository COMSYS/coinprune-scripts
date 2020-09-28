""" This module contains base functionality for reading from snapshot files. """

import struct


# File and binary helpers

def read_at_pos(file_handler, length, offset=None):
    if offset is not None:
        old_pos = file_handler.tell()
        file_handler.seek(offset)
    res = file_handler.read(length)
    if offset is not None:
        file_handler.seek(old_pos)
    return res


def read_int(data):
    return struct.unpack('<I', data)[0]


def read_int_file(file_handler, offset=None):
    return read_int(read_at_pos(file_handler, 4, offset))


def write_int(n):
    return struct.pack('<I', n)


def write_int_file(file_handler, n):
    file_handler.write(write_int(n))


def read_charint(data):
    return struct.unpack('<B', data)[0]


def read_charint_file(file_handler, offset=None):
    return read_charint(read_at_pos(file_handler, 1, offset))


def write_charint(n):
    return struct.pack('<B', n)


def write_charint_file(file_handler, n):
    file_handler.write(write_charint(n))


def read_shortint(data):
    return struct.unpack('<H', data)[0]


def read_shortint_file(file_handler, offset=None):
    return read_shortint(read_at_pos(file_handler, 2, offset))


def write_shortint(n):
    return struct.pack('<H', n)


def write_shortint_file(file_handler, n):
    file_handler.write(write_shortint(n))


def read_longint(data):
    return struct.unpack('<Q', data)[0]


def read_longint_file(file_handler, offset=None):
    return read_longint(read_at_pos(file_handler, 8, offset))


def write_longint(n):
    return struct.pack('<Q', n)


def write_longint_file(file_handler, n):
    file_handler.write(write_longint(n))


# Bitcoin-specific base readings

# See src/serialize.h:235
def read_compact_int(data):
    """ Returns (int, data_length). """
    res = read_charint(data[0])
    if res < 253:
        return res, 1
    elif res == 253:
        return read_shortint(data[1:(1 + 2)]), 3
    elif res == 254:
        return read_int(data[1:(1 + 4)]), 5
    else:
        return read_longint(data[1:(1 + 8)]), 9


def read_compact_int_file(file_handler, offset=None):
    res = read_charint_file(file_handler, offset)
    if res < 253:
        if offset is not None:
            new_offset = offset + 1
        return res, 1
    elif res == 253:
        res = read_shortint_file(file_handler, offset=((offset + 1) if offset is not None else None))
        if offset is not None:
            new_offset = offset + 3
    elif res == 254:
        res = read_int_file(file_handler, offset=((offset + 1) if offset is not None else None))
        if offset is not None:
            new_offset = offset + 5
    else:
        res = read_longint_file(file_handler, offset=((offset + 1) if offset is not None else None))
        if offset is not None:
            new_offset = offset + 9

    if offset is None:
        return res
    else:
        return res, new_offset


def write_compact_int(n):
    if n < 253:
        return write_charint(n)
    elif n <= 2**16 - 1:
        return write_charint(253) + write_shortint(n)
    elif n <= 2**32 - 1:
        return write_charint(254) + write_int(n)
    else:
        return write_charint(255) + write_longint(n)


def write_compact_int_file(file_handler, n):
    file_handler.write(write_compact_int(n))


# VARINTs


def read_varint(data):
    n = 0
    i = 0
    while True:
        b = data[i]
        i += 1
        n = (n << 7) | (b & 0x7F)
        if b & 0x80:
            n += 1
        else:
            return n, i


def read_varint_file(file_handler):
    n = 0
    while True:
        b = file_handler.read(1)
        b = struct.unpack('B', b)[0]
        n = (n << 7) | (b & 0x7F)
        if b & 0x80:
            n += 1
        else:
            return n


# See src/serialize.h:372
def write_varint(n):
    res = b''
    n = int(n)
    length = 0
    while True:
        res += struct.pack('<B', (n & 0x7F) | (0x80 if length else 0x00))
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
        length += 1
    return res[::-1]


def write_varint_file(file_handler, n):
    file_handler.write(write_varint(n))
