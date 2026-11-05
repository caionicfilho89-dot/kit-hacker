# 🛡️ Kit do Hacker

Canivete **offline** pra quem está estudando segurança / bug bounty: codificar e decodificar,
calcular hashes, identificar tipo de hash, ler JWT, converter timestamps, gerar tokens e
achar caracteres invisíveis. Nada sai do seu PC.

## Funções (20)

- **Codificar/Decodificar:** Base64, Base64 URL-safe, URL (%XX), Entidades HTML, Hexadecimal,
  Binário, ROT13, Unicode escape (`\uXXXX`), Decodificar automático (desembrulha camadas)
- **Hash:** hashes do texto (MD5, SHA-1, SHA-256, SHA-512, SHA3-256, CRC32), HMAC, hash de arquivo
- **Identificar hash:** palpite por tamanho/charset/prefixo (MD5, NTLM, SHA*, bcrypt, `$6$`, `$1$`, Argon2, MySQL5…)
- **JWT:** decodificar (header, payload, datas iat/nbf/exp, expirado?) e verificar assinatura HS256/384/512
- **Tempo:** timestamp → data e data → timestamp (segundos/ms, local e UTC)
- **Gerar:** UUID v4, token aleatório (hex/base64/base64url via `secrets`)
- **Ver dados:** inspecionar texto (bytes UTF-8, zero-width, RTL, homóglifos)

## Como usar

```
pip install -r requirements.txt
python kit_hacker.pyw
```

Testes: `python test_kh.py`

## Licença

MIT
