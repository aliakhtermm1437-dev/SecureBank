import pytest

from securebank_shared.crypto import (
    aesgcm_decrypt,
    aesgcm_encrypt,
    constant_time_eq,
    gen_key_aes256,
    hmac_sign,
    hmac_verify,
)


def test_aesgcm_roundtrip() -> None:
    k = gen_key_aes256()
    ct = aesgcm_encrypt(k, b"hello world")
    pt = aesgcm_decrypt(k, ct.to_bytes())
    assert pt == b"hello world"


def test_aesgcm_rejects_short_blob() -> None:
    k = gen_key_aes256()
    with pytest.raises(ValueError):
        aesgcm_decrypt(k, b"123")


def test_aesgcm_wrong_key_fails() -> None:
    k1, k2 = gen_key_aes256(), gen_key_aes256()
    blob = aesgcm_encrypt(k1, b"secret").to_bytes()
    with pytest.raises(Exception):
        aesgcm_decrypt(k2, blob)


def test_hmac_roundtrip() -> None:
    k = b"\x00" * 32
    sig = hmac_sign(k, b"data")
    assert hmac_verify(k, b"data", sig)
    assert not hmac_verify(k, b"data-tampered", sig)


def test_constant_time_eq() -> None:
    assert constant_time_eq("abc", "abc")
    assert not constant_time_eq("abc", "abd")
    assert constant_time_eq(b"\x01\x02", b"\x01\x02")
