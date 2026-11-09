import copy

import pytest
from cryptography.exceptions import InvalidTag

import crypto_lib as c


@pytest.fixture(scope="module")
def keys():
    return c.generate_keypair(), c.generate_keypair()  # A (remetente), B (destinatário)


def test_roundtrip(keys):
    a, b = keys
    pkg = c.secure_send(b"ola", b.public_key(), a)
    assert c.secure_receive(pkg, b, a.public_key()) == b"ola"


def test_ciphertext_tampering_detected_by_signature(keys):
    a, b = keys
    pkg = c.secure_send(b"ola", b.public_key(), a)
    bad = copy.deepcopy(pkg)
    raw = bytearray(c._b64d(bad["envelope"]["ciphertext"]))
    raw[0] ^= 1
    bad["envelope"]["ciphertext"] = c._b64e(bytes(raw))
    with pytest.raises(ValueError):
        c.secure_receive(bad, b, a.public_key())


def test_gcm_detects_tampering_without_signature(keys):
    _, b = keys
    env = c.hybrid_encrypt(b"ola", b.public_key())
    raw = bytearray(c._b64d(env["ciphertext"]))
    raw[0] ^= 1
    env["ciphertext"] = c._b64e(bytes(raw))
    with pytest.raises(InvalidTag):
        c.hybrid_decrypt(env, b)


def test_wrong_recipient_cannot_decrypt(keys):
    a, b = keys
    outro = c.generate_keypair()
    env = c.hybrid_encrypt(b"segredo", b.public_key())
    with pytest.raises(Exception):
        c.hybrid_decrypt(env, outro)


def test_signature_valid_and_invalid(keys):
    a, _ = keys
    sig = c.sign(b"texto", a)
    assert c.verify(b"texto", sig, a.public_key())
    assert not c.verify(b"texto!", sig, a.public_key())


def test_signature_from_other_key_rejected(keys):
    a, b = keys
    sig = c.sign(b"texto", b)
    assert not c.verify(b"texto", sig, a.public_key())


def test_nonce_is_unique(keys):
    _, b = keys
    e1 = c.hybrid_encrypt(b"x", b.public_key())
    e2 = c.hybrid_encrypt(b"x", b.public_key())
    assert e1["nonce"] != e2["nonce"] and e1["ciphertext"] != e2["ciphertext"]


def test_save_and_load_keys(tmp_path, keys):
    a, _ = keys
    priv, pub = c.save_keypair(a, tmp_path, "t", password=b"pw")
    loaded = c.load_private_key(priv, b"pw")
    sig = c.sign(b"m", loaded)
    assert c.verify(b"m", sig, c.load_public_key(pub))
