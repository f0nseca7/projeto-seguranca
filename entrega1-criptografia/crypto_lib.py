"""Entrega 1 - Criptografia assimétrica e confiança.

Biblioteca com:
  * geração de par de chaves RSA-3072 (e salvamento em PEM);
  * cifragem híbrida: AES-256-GCM (conteúdo) + RSA-OAEP/SHA-256 (chave);
  * assinatura digital RSA-PSS/SHA-256.

Usa apenas a biblioteca consolidada `cryptography` (nenhum algoritmo próprio).
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_SIZE = 3072          # ~128 bits de segurança (NIST SP 800-57)
RSA_PUBLIC_EXPONENT = 65537
AES_KEY_BITS = 256
GCM_NONCE_BYTES = 12         # 96 bits: tamanho recomendado para GCM


# ----------------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------------
def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _pss() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.DIGEST_LENGTH,
    )


# ----------------------------------------------------------------------------
# Gestão de chaves
# ----------------------------------------------------------------------------
def generate_keypair() -> rsa.RSAPrivateKey:
    """Gera um par de chaves RSA (a pública é derivada da privada)."""
    return rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE
    )


def save_keypair(private_key: rsa.RSAPrivateKey, directory: str | Path,
                 name: str, password: bytes | None = None) -> tuple[Path, Path]:
    """Salva a chave privada (PEM, criptografada com senha se informada) e a pública."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    priv_path = directory / f"{name}_private.pem"
    pub_path = directory / f"{name}_public.pem"

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
    )
    os.chmod(priv_path, 0o600)  # somente o dono lê/escreve (em sistemas POSIX)

    pub_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_path, pub_path


def load_private_key(path: str | Path, password: bytes | None = None):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=password)


def load_public_key(path: str | Path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


# ----------------------------------------------------------------------------
# Cifragem híbrida (sigilo): AES-256-GCM + RSA-OAEP
# ----------------------------------------------------------------------------
def hybrid_encrypt(message: bytes, recipient_public_key) -> dict:
    """Cifra `message` para o dono da chave pública.

    1. Gera chave AES-256 aleatória (descartável, uma por mensagem).
    2. Cifra a mensagem com AES-GCM (confidencialidade + integridade).
    3. Encapsula a chave AES com RSA-OAEP usando a chave pública do destinatário.
    """
    aes_key = AESGCM.generate_key(bit_length=AES_KEY_BITS)
    nonce = os.urandom(GCM_NONCE_BYTES)
    ciphertext = AESGCM(aes_key).encrypt(nonce, message, None)  # ciphertext + tag
    wrapped_key = recipient_public_key.encrypt(aes_key, _oaep())
    return {
        "alg": "RSA-OAEP-SHA256+AES-256-GCM",
        "wrapped_key": _b64e(wrapped_key),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }


def hybrid_decrypt(envelope: dict, recipient_private_key) -> bytes:
    """Decifra o envelope. Levanta exceção se algo tiver sido adulterado."""
    aes_key = recipient_private_key.decrypt(_b64d(envelope["wrapped_key"]), _oaep())
    return AESGCM(aes_key).decrypt(
        _b64d(envelope["nonce"]), _b64d(envelope["ciphertext"]), None
    )


# ----------------------------------------------------------------------------
# Assinatura digital (autenticidade + integridade): RSA-PSS
# ----------------------------------------------------------------------------
def sign(message: bytes, signer_private_key) -> bytes:
    return signer_private_key.sign(message, _pss(), hashes.SHA256())


def verify(message: bytes, signature: bytes, signer_public_key) -> bool:
    try:
        signer_public_key.verify(signature, message, _pss(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ----------------------------------------------------------------------------
# Pacote completo: cifrar para o destinatário E assinar pelo remetente
# (encrypt-then-sign: a assinatura cobre o envelope cifrado inteiro)
# ----------------------------------------------------------------------------
def _canonical(envelope: dict) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


def secure_send(message: bytes, recipient_public_key, sender_private_key) -> dict:
    envelope = hybrid_encrypt(message, recipient_public_key)
    signature = sign(_canonical(envelope), sender_private_key)
    return {"envelope": envelope, "signature": _b64e(signature)}


def secure_receive(package: dict, recipient_private_key, sender_public_key) -> bytes:
    """Verifica a assinatura PRIMEIRO; só então decifra."""
    envelope = package["envelope"]
    if not verify(_canonical(envelope), _b64d(package["signature"]), sender_public_key):
        raise ValueError("Assinatura inválida: remetente não autenticado ou pacote adulterado.")
    return hybrid_decrypt(envelope, recipient_private_key)
