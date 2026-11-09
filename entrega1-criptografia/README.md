# Entrega 1 — Criptografia assimétrica e confiança

Projeto Integrador: Segurança Aplicada ao Desenvolvimento | Segurança da Informação | Universidade Tiradentes

## 1. Problema e objetivo

Um serviço A precisa enviar uma mensagem a um serviço B de forma que:

- **só B consiga ler** (sigilo);
- **B tenha certeza de que A enviou e de que nada foi alterado** (autenticidade e integridade).

Esta solução implementa **as duas alternativas pedidas** (a atividade exige uma delas, "OU"): cifragem híbrida **e** assinatura digital, combinadas no fluxo *encrypt-then-sign*.

## 2. Ambiente e tecnologias

- Python 3.10+
- Biblioteca [`cryptography`](https://cryptography.io) (consolidada; nenhum algoritmo próprio foi implementado)
- `pytest` para os testes

## 3. Algoritmos e parâmetros

| Função | Algoritmo | Parâmetros | Justificativa |
|---|---|---|---|
| Par de chaves | RSA | 3072 bits, e = 65537 | ~128 bits de segurança (NIST SP 800-57) |
| Cifrar conteúdo | AES-GCM | chave 256 bits, nonce 96 bits aleatório por mensagem | cifra autenticada: sigilo + integridade (tag de 128 bits) |
| Encapsular a chave AES | RSA-OAEP | SHA-256, MGF1-SHA-256 | padding seguro contra ataques de texto cifrado escolhido (evita PKCS#1 v1.5) |
| Assinatura | RSA-PSS | SHA-256, MGF1-SHA-256, salt = 32 bytes | esquema probabilístico com prova de segurança |

**Por que híbrida?** RSA só cifra mensagens menores que o módulo e é lento. Por isso a mensagem é cifrada com AES (rápido, qualquer tamanho) e apenas a chave AES (32 bytes) é cifrada com RSA.

### Fluxo

```
Envio (A -> B):
  1. chave AES-256 aleatória + nonce de 12 bytes
  2. ciphertext = AES-GCM(chave AES, nonce, mensagem)
  3. wrapped_key = RSA-OAEP(pública de B, chave AES)
  4. signature = RSA-PSS(privada de A, envelope canônico em JSON)

Recebimento (B):
  1. verifica a assinatura com a pública de A  -> falha: rejeita
  2. recupera a chave AES com a privada de B
  3. decifra e valida a tag do AES-GCM          -> falha: rejeita
```

A assinatura é verificada **antes** de decifrar, para não processar dados de origem não confiável.

## 4. Execução

```bash
cd entrega1-criptografia
python -m pip install -r requirements.txt
python demo.py        # demonstração: sucesso e falhas após adulteração
python -m pytest -q   # 8 testes automatizados
```

Se o executável `pip` estiver bloqueado no sistema, `python -m pip` resolve (usado acima). A pasta `keys/` é criada pelo `demo.py` e não é versionada (`.gitignore`).

Arquivos: `crypto_lib.py` (biblioteca), `demo.py` (demonstração), `test_crypto.py` (testes).

## 5. Testes e evidências

`python demo.py` demonstra:

1. Fluxo normal: mensagem cifrada, assinada, verificada e decifrada com sucesso.
2. Adulteração de 1 bit no texto cifrado: **rejeitada pela assinatura**.
3. Atacante refaz a assinatura com a própria chave: **rejeitada** (não é a chave de A).
4. Somente cifragem, com adulteração: **AES-GCM levanta `InvalidTag`**.
5. Somente assinatura: válida no texto original, **inválida** com 1 caractere alterado.

Saídas salvas em `evidencia_demo.txt` e `evidencia_testes.txt` (8 testes passando). Cole prints ou grave um vídeo da execução como evidência adicional.

## 6. Sigilo x autenticidade

- **Sigilo (confidencialidade):** impede que terceiros leiam o conteúdo. Obtido cifrando com a chave **pública** do destinatário; só a privada dele decifra. Não prova quem enviou: qualquer pessoa conhece a chave pública de B e pode cifrar uma mensagem para ele.
- **Autenticidade (e integridade):** prova a origem e que o conteúdo não mudou. Obtida assinando com a chave **privada** do remetente; qualquer um verifica com a pública. Não esconde o conteúdo.

São propriedades independentes, por isso o fluxo usa as duas.

## 7. Certificados digitais e PKI

Quando B recebe a chave pública de A, como saber que ela realmente pertence a A e não a um atacante (ataque *man-in-the-middle*)? Um **certificado digital** (padrão X.509) vincula uma identidade (nome, domínio, organização) a uma chave pública, e é **assinado por uma Autoridade Certificadora (AC)** em que se confia.

A **PKI (Infraestrutura de Chaves Públicas)** é o conjunto de ACs, políticas, certificados, listas/consultas de revogação (CRL/OCSP) e processos que sustentam essa confiança. A validação segue a **cadeia de confiança**: certificado do serviço, AC intermediária e AC raiz presente no repositório de confiança do sistema. Exemplos: HTTPS/TLS, ICP-Brasil, certificados de assinatura de documentos.

Neste laboratório as chaves públicas são trocadas diretamente (arquivos `.pem`), simulando um canal já confiável. Em produção, cada serviço apresentaria um certificado emitido por uma AC.

## 8. Gestão de chaves

- Chaves privadas salvas em PEM/PKCS#8 **criptografadas com senha** (`BestAvailableEncryption`) e permissão `0600`.
- Chaves privadas **nunca** são versionadas: adicione `keys/` ao `.gitignore`.
- Chave AES **efêmera**: uma nova por mensagem, nunca reutilizada nem armazenada.
- Nonce aleatório de 96 bits por mensagem (nunca reutilizar nonce com a mesma chave no GCM).
- As senhas do `demo.py` são apenas de laboratório; em produção use um cofre de segredos (Vault, KMS) e variáveis de ambiente.

## 9. Riscos, limitações e melhorias

- Sem certificados/PKI: não há validação de identidade da chave pública (ver seção 7).
- Sem proteção contra **replay**: um pacote válido capturado pode ser reenviado. Melhoria: incluir timestamp/ID único assinado e rejeitar repetidos.
- Sem rotação nem revogação de chaves.
- Chave privada em disco: melhor guardá-la em HSM/KMS.
- Sem sigilo de metadados (tamanho da mensagem, quem se comunica).
- Possível melhoria: trocar RSA-PSS por **Ed25519** (chaves menores, mais rápido) e usar ECDH/X25519 em vez de RSA-OAEP.

## 10. Referências

- Documentação oficial da biblioteca `cryptography`: https://cryptography.io/en/latest/
- NIST SP 800-57 Part 1 — Recommendation for Key Management.
- RFC 8017 — PKCS #1 v2.2 (RSA-OAEP e RSA-PSS).
- NIST SP 800-38D — Galois/Counter Mode (GCM).
- RFC 5280 — Certificados X.509 e perfil de CRL.
- OWASP Cryptographic Storage Cheat Sheet.
