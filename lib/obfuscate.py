""" This module has functionality regarding content obfuscation. """

import hashlib
from ecdsa import SECP256k1
from ecdsa.util import number_to_string


# https://bitcoin.stackexchange.com/a/38253/22795
threshold_value = SECP256k1.order >> 1


# https://github.com/warner/python-ecdsa/issues/121#issuecomment-536637013
def encode_commitment(commitment):
    enc_x = number_to_string(commitment.x, SECP256k1.order)
    return (b'\x03' + enc_x) if commitment.y % 2 else (b'\x02' + enc_x)


def obfuscate_payload(data):
    private_value = data
    private_value_int = int.from_bytes(private_value, byteorder='big', signed='false')
    # Apply OP_HASH256 until value is suitable, if too long for SECP256k1
    while private_value_int >= threshold_value:
        private_value = hashlib.sha256(private_value).digest()
        private_value = hashlib.sha256(private_value).digest()
        private_value_int = int.from_bytes(private_value, byteorder='big', signed='false')

    public_value_int = private_value_int * SECP256k1.generator
    return encode_commitment(public_value_int)


def verify_obfuscated_payload(data, commitment):
    return obfuscate_payload(data) == commitment


def encode_commitment_simple(commitment):
    return commitment


def obfuscate_payload_simple(data):
    return encode_commitment_simple(hashlib.sha256(data).digest())


def verify_obfuscated_payload_simple(data, commitment):
    return obfuscate_payload_simple(data) == commitment
