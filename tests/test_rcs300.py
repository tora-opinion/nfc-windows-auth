import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'src'))

from rcs300 import (
    ReaderProtocolError,
    parse_express_card_response,
    parse_tlvs,
)


def _sensf_res():
    idm = bytes.fromhex('0102030405060708')
    pmm = bytes.fromhex('1112131415161718')
    return bytes([0x12, 0x01]) + idm + pmm


def _tagged_response(length_encoding):
    value = _sensf_res()
    return bytes([0x97]) + length_encoding(len(value)) + value


def test_parse_tlv_one_byte_length():
    assert parse_tlvs(b'\x97\x03abc') == [(0x97, b'abc')]


def test_parse_tlv_extended_lengths_81_and_82():
    value_81 = b'a' * 128
    value_82 = b'b' * 256

    assert parse_tlvs(b'\x97\x81\x80' + value_81) == [(0x97, value_81)]
    assert parse_tlvs(b'\x97\x82\x01\x00' + value_82) == [(0x97, value_82)]


@pytest.mark.parametrize('length_encoding', [
    lambda size: bytes([size]),
    lambda size: bytes([0x81, size]),
    lambda size: bytes([0x82, size >> 8, size & 0xFF]),
])
def test_express_card_parser_extracts_idm_without_offset_regression(length_encoding):
    parsed = parse_express_card_response(_tagged_response(length_encoding))

    assert parsed == (
        bytes.fromhex('0102030405060708'),
        bytes.fromhex('1112131415161718'),
    )


@pytest.mark.parametrize('response', [
    b'\x97',
    b'\x97\x81',
    b'\x97\x82\x00',
    b'\x97\x05abc',
    b'\xff',
    b'\x97\x80',
])
def test_parse_tlv_rejects_truncated_or_garbage_input(response):
    with pytest.raises(ValueError):
        parse_tlvs(response)


def test_express_card_parser_treats_no_card_status_as_empty():
    assert parse_express_card_response(b'\xC0\x03\x00\x64\x00') is None


def test_express_card_parser_rejects_short_sensf_response():
    with pytest.raises(ReaderProtocolError):
        parse_express_card_response(b'\x97\x02\x02\x01')
