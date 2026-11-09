# Projeto Integrador: Segurança Aplicada ao Desenvolvimento

**Estudante:** Adriano Santana Fonseca
**Curso:** Ciência da Computação — Universidade Tiradentes
**Disciplina:** Segurança da Informação
**Docente:** Ana Carla do Nascimento Santos

## Objetivo

Implementar, testar, analisar e justificar controles de segurança em uma aplicação e em seu ambiente de execução, em quatro entregas progressivas. Todos os testes são feitos em ambiente próprio, com dados fictícios, e as soluções criptográficas usam apenas bibliotecas consolidadas (nenhum algoritmo próprio).

## Entregas

| Entrega | Tema | Pasta | Status |
|---|---|---|---|
| 1 | Criptografia assimétrica e confiança (AES-GCM + RSA-OAEP + RSA-PSS) | [entrega1-criptografia](entrega1-criptografia/) | Concluída |
| 2 | Hash e autenticação segura | `entrega2-hash-senhas/` | Pendente |
| 3 | Varredura de portas e serviços (Nmap) | `entrega3-nmap/` | Pendente |
| 4 | Auditoria e correção de vulnerabilidades | `entrega4-auditoria/` | Pendente |

Cada pasta contém o código, o README da entrega (algoritmos, parâmetros, execução, testes, riscos e referências) e as evidências de execução.

## Como executar

Requisitos: Python 3.10+. As instruções detalhadas de cada entrega estão no README da respectiva pasta. Exemplo para a Entrega 1:

```bash
cd entrega1-criptografia
python -m pip install -r requirements.txt
python demo.py
python -m pytest -q
```

## Observação de segurança

Chaves privadas e segredos nunca são versionados (ver `.gitignore`). As senhas presentes nos códigos de demonstração são apenas de laboratório.
