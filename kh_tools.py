"""Catálogo das funções do Kit do Hacker: categoria, nome, descrição, campos e execução.
A interface monta tudo a partir daqui."""
import kh_core as c

MODE = ("combo", "mode", "Modo:", [c.ENC, c.DEC])
TEXT = ("text", "text", "Entrada:", "Cole ou digite o texto aqui…")


def _codec(fn, **kw):
    return lambda v: fn(v["text"], v["mode"], **kw)


def _hmac(v):
    if not v["key"]:
        return "Digite a chave (segredo) do HMAC."
    return f"HMAC-{v['algo'].upper()}:\n{c.hmac_text(v['text'], v['key'], v['algo'])}"


def _file(v):
    if not v["path"]:
        return "Escolha um arquivo em “📂 Escolher…”."
    return c.hash_file(v["path"])


def _jwt_verify(v):
    if not v["secret"]:
        return "Digite o segredo pra conferir a assinatura."
    return c.jwt_verify(v["token"], v["secret"])[1]


def _date_ts(v):
    return c.date_to_ts(v["text"], utc=v["tz"] == "UTC")


TOOLS = [
    # ---- Codificar/Decodificar
    dict(id="b64", cat="Codificar/Decodificar", name="Base64",
         desc="Base64 padrão (o “==” no final é a pista). Muito usado em cookies, cabeçalhos e APIs.",
         fields=[MODE, TEXT], run=_codec(c.b64), live=True),
    dict(id="b64url", cat="Codificar/Decodificar", name="Base64 URL-safe",
         desc="Variante que troca + / por - _ e geralmente sem “=”. É a usada em JWT.",
         fields=[MODE, TEXT], run=_codec(c.b64, urlsafe=True), live=True),
    dict(id="url", cat="Codificar/Decodificar", name="URL (%XX)",
         desc="Percent-encoding: espaço vira %20, / vira %2F… Comum em parâmetros de URL.",
         fields=[MODE, TEXT], run=_codec(c.url), live=True),
    dict(id="html", cat="Codificar/Decodificar", name="Entidades HTML",
         desc="< vira &lt;, \" vira &quot;… Útil pra entender XSS e como o site escapa a saída.",
         fields=[MODE, TEXT], run=_codec(c.html_ent), live=True),
    dict(id="hex", cat="Codificar/Decodificar", name="Hexadecimal",
         desc="Cada byte vira 2 dígitos hex. Na decodificação aceita espaços, 0x, \\x e dois-pontos.",
         fields=[MODE, TEXT], run=_codec(c.hexa), live=True),
    dict(id="bin", cat="Codificar/Decodificar", name="Binário",
         desc="Cada byte em 8 bits (0 e 1).",
         fields=[MODE, TEXT], run=_codec(c.binario), live=True),
    dict(id="rot13", cat="Codificar/Decodificar", name="ROT13",
         desc="Gira cada letra 13 posições. Aplicar duas vezes volta ao original.",
         fields=[TEXT], run=lambda v: c.rot13(v["text"]), live=True),
    dict(id="uni", cat="Codificar/Decodificar", name="Unicode escape (\\uXXXX)",
         desc="Escreve caracteres como \\u00e7. Aparece muito em JSON e JavaScript.",
         fields=[MODE, TEXT], run=_codec(c.unicode_esc), live=True),
    dict(id="auto", cat="Codificar/Decodificar", name="Decodificar automático",
         desc="Tenta descobrir e desembrulhar camadas (Base64 → URL → Hex…) e mostra cada passo.",
         fields=[TEXT], run=lambda v: c.auto_decode(v["text"]), live=True),
    # ---- Hash
    dict(id="hashes", cat="Hash", name="Hashes do texto",
         desc="MD5, SHA-1, SHA-256, SHA-512, SHA3-256 e CRC32 de uma vez (texto em UTF-8).",
         fields=[TEXT], run=lambda v: c.hashes_text(v["text"]), live=True),
    dict(id="hmac", cat="Hash", name="HMAC",
         desc="Hash com chave secreta — é assim que webhooks e JWT HS* assinam mensagens.",
         fields=[("line", "key", "Chave:", "segredo"),
                 ("combo", "algo", "Algoritmo:", ["sha256", "sha1", "md5", "sha384", "sha512"]),
                 TEXT], run=_hmac, live=True),
    dict(id="hfile", cat="Hash", name="Hash de arquivo",
         desc="Calcula os hashes de um arquivo pra conferir se é o original (compare com o do site).",
         fields=[("file", "path", "Arquivo:", "")], run=_file, live=False),
    # ---- Identificar
    dict(id="ident", cat="Identificar hash", name="Identificar hash",
         desc="Palpita o tipo pelo tamanho, caracteres e prefixo ($2b$, $6$, *…). É só um palpite!",
         fields=[("line", "text", "Hash:", "ex.: 5f4dcc3b5aa765d61d8327deb882cf99")],
         run=lambda v: c.identify_report(v["text"]), live=True),
    # ---- JWT
    dict(id="jwt", cat="JWT", name="Decodificar JWT",
         desc="Mostra header e payload, as datas (iat/nbf/exp) e se o token já expirou.",
         fields=[("text", "token", "Token:", "eyJhbGciOi…")],
         run=lambda v: c.jwt_decode(v["token"]) if v["token"].strip() else "Cole um JWT.", live=True),
    dict(id="jwtv", cat="JWT", name="Verificar assinatura JWT",
         desc="Confere a assinatura HS256/HS384/HS512 com o segredo que você informar.",
         fields=[("line", "secret", "Segredo:", "segredo do servidor"),
                 ("text", "token", "Token:", "eyJhbGciOi…")], run=_jwt_verify, live=True),
    # ---- Tempo
    dict(id="ts2d", cat="Tempo", name="Timestamp → data",
         desc="Unix timestamp (segundos ou milissegundos — detecta sozinho) em data UTC e local.",
         fields=[("line", "text", "Timestamp:", "1700000000")],
         run=lambda v: c.ts_to_date(v["text"]), live=True),
    dict(id="d2ts", cat="Tempo", name="Data → timestamp",
         desc="Data legível em Unix timestamp (segundos e milissegundos).",
         fields=[("combo", "tz", "Fuso:", ["Local", "UTC"]),
                 ("line", "text", "Data:", "25/12/2026 18:30:00")], run=_date_ts, live=True),
    # ---- Gerar
    dict(id="uuid", cat="Gerar", name="UUID v4",
         desc="Identificadores aleatórios (UUID versão 4).",
         fields=[("spin", "n", "Quantidade:", 1, 100, 5)],
         run=lambda v: c.gen_uuids(v["n"]), live=False),
    dict(id="token", cat="Gerar", name="Token aleatório",
         desc="Token criptograficamente seguro (módulo secrets) — bom pra segredos e chaves de API.",
         fields=[("spin", "n", "Bytes:", 1, 512, 32),
                 ("combo", "fmt", "Formato:", ["hex", "base64", "base64url"])],
         run=lambda v: c.gen_token(v["n"], v["fmt"]), live=False),
    # ---- Ver dados
    dict(id="insp", cat="Ver dados", name="Inspecionar texto",
         desc="Conta caracteres e bytes UTF-8 e destaca caracteres invisíveis (zero-width, RTL…).",
         fields=[TEXT], run=lambda v: c.inspect_text(v["text"]), live=True),
]
