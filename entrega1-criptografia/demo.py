"""Demonstração da Entrega 1: sucesso e falha após adulteração."""
import base64
import copy

from cryptography.exceptions import InvalidTag

import crypto_lib as c


def titulo(txt: str) -> None:
    print(f"\n{'=' * 70}\n{txt}\n{'=' * 70}")


def flip_byte(b64_text: str) -> str:
    """Altera 1 bit do dado (simula adulteração em trânsito)."""
    raw = bytearray(base64.b64decode(b64_text))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def main() -> None:
    titulo("1) Geração e salvamento dos pares de chaves (Serviço A e Serviço B)")
    chave_a = c.generate_keypair()   # remetente (assina)
    chave_b = c.generate_keypair()   # destinatário (decifra)
    c.save_keypair(chave_a, "keys", "servico_a", password=b"senha-de-laboratorio-A")
    c.save_keypair(chave_b, "keys", "servico_b", password=b"senha-de-laboratorio-B")
    print("Chaves salvas na pasta keys/ (privadas protegidas por senha).")

    mensagem = "Transferir R$ 100,00 para a conta 12345 (mensagem fictícia)".encode()

    titulo("2) Fluxo normal: A cifra para B e assina; B verifica e decifra")
    pacote = c.secure_send(mensagem, chave_b.public_key(), chave_a)
    print("Envelope cifrado (trecho):", pacote["envelope"]["ciphertext"][:60], "...")
    recebida = c.secure_receive(pacote, chave_b, chave_a.public_key())
    print("SUCESSO -> mensagem recebida:", recebida.decode())

    titulo("3) Adulteração do TEXTO CIFRADO em trânsito")
    adulterado = copy.deepcopy(pacote)
    adulterado["envelope"]["ciphertext"] = flip_byte(adulterado["envelope"]["ciphertext"])
    try:
        c.secure_receive(adulterado, chave_b, chave_a.public_key())
    except ValueError as e:
        print("FALHA detectada pela ASSINATURA ->", e)

    titulo("4) Adulteração com assinatura 'refeita' por um atacante (outra chave)")
    atacante = c.generate_keypair()
    falsificado = copy.deepcopy(adulterado)
    falsificado["signature"] = c._b64e(c.sign(c._canonical(falsificado["envelope"]), atacante))
    try:
        c.secure_receive(falsificado, chave_b, chave_a.public_key())
    except ValueError as e:
        print("FALHA detectada: assinatura não pertence ao remetente legítimo ->", e)

    titulo("5) Só a cifragem (sem assinatura): o AES-GCM também detecta adulteração")
    env = c.hybrid_encrypt(mensagem, chave_b.public_key())
    env["ciphertext"] = flip_byte(env["ciphertext"])
    try:
        c.hybrid_decrypt(env, chave_b)
    except InvalidTag:
        print("FALHA detectada pela tag de autenticação do AES-GCM (InvalidTag).")

    titulo("6) Só a assinatura: mensagem pública, mas autêntica e íntegra")
    texto = b"Comunicado oficial: manutencao as 22h."
    assinatura = c.sign(texto, chave_a)
    print("Assinatura válida (original):    ", c.verify(texto, assinatura, chave_a.public_key()))
    print("Assinatura válida (texto alterado):", c.verify(texto + b"!", assinatura, chave_a.public_key()))

    titulo("7) Sigilo != Autenticidade")
    print("Cifrar com a chave pública de B garante SIGILO (só B lê), mas qualquer um")
    print("pode ter cifrado. Assinar com a chave privada de A garante AUTENTICIDADE")
    print("e INTEGRIDADE, mas não esconde o conteúdo. Por isso usamos os dois.")


if __name__ == "__main__":
    main()
