"""Lógica do Kit do Hacker: codificar/decodificar, hashes, identificar hash, JWT,
timestamps, geradores e inspeção de texto. Só biblioteca padrão, sem rede."""
import base64
import binascii
import codecs
import hashlib
import hmac
import html
import json
import re
import secrets
import unicodedata
import urllib.parse
import uuid
import zlib
from datetime import datetime, timezone

ENC = "Codificar"
DEC = "Decodificar"


# ---------------------------------------------------------------- codificação
def b64(text, mode=ENC, urlsafe=False):
    if mode == ENC:
        raw = text.encode("utf-8")
        return (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode("ascii")
    s = re.sub(r"\s+", "", text)
    if urlsafe or "-" in s or "_" in s:
        s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    raw = base64.b64decode(s, validate=True)
    return _bytes_to_text(raw)


def _bytes_to_text(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return "(bytes não-UTF-8, mostrados em hex)\n" + raw.hex(" ")


def url(text, mode=ENC):
    if mode == ENC:
        return urllib.parse.quote(text, safe="")
    return urllib.parse.unquote_plus(text) if "+" in text and "%20" not in text else urllib.parse.unquote(text)


def html_ent(text, mode=ENC):
    if mode == ENC:
        return html.escape(text, quote=True)
    return html.unescape(text)


def hexa(text, mode=ENC):
    if mode == ENC:
        return text.encode("utf-8").hex()
    s = re.sub(r"0x|\\x|[\s:,-]", "", text, flags=re.I)
    return _bytes_to_text(bytes.fromhex(s))


def binario(text, mode=ENC):
    if mode == ENC:
        return " ".join(f"{b:08b}" for b in text.encode("utf-8"))
    s = re.sub(r"[^01]", "", text)
    if not s or len(s) % 8:
        raise ValueError("A quantidade de bits precisa ser múltipla de 8.")
    return _bytes_to_text(bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8)))


def rot13(text, mode=ENC):
    return codecs.encode(text, "rot13")


def unicode_esc(text, mode=ENC):
    if mode == ENC:
        out = []
        for ch in text:
            cp = ord(ch)
            if 32 <= cp < 127:
                out.append(ch)
            elif cp <= 0xFFFF:
                out.append(f"\\u{cp:04x}")
            else:
                out.append(f"\\U{cp:08x}")
        return "".join(out)

    def rep(m):
        return chr(int(m.group(1) or m.group(2) or m.group(3), 16))
    return re.sub(r"\\u\{([0-9a-fA-F]+)\}|\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})", rep, text)


def _printable(s):
    if not s:
        return False
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return ok / len(s) > 0.95


def _try_layers(s):
    """Retorna (nome, resultado) da primeira camada que parece fazer sentido."""
    t = s.strip()
    if re.fullmatch(r"(?:[01]{8}\s*)+", t):
        return "Binário", binario(t, DEC)
    if re.fullmatch(r"(?:0x)?(?:[0-9a-fA-F]{2})+", t) and len(t) >= 4:
        try:
            r = bytes.fromhex(t[2:] if t.lower().startswith("0x") else t).decode("utf-8")
            if _printable(r):
                return "Hex", r
        except (ValueError, UnicodeDecodeError):
            pass
    if re.search(r"%[0-9a-fA-F]{2}", t):
        r = urllib.parse.unquote(t)
        if r != t:
            return "URL", r
    if re.search(r"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", t):
        r = html.unescape(t)
        if r != t:
            return "Entidades HTML", r
    if re.search(r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}", t):
        r = unicode_esc(t, DEC)
        if r != t:
            return "Unicode escape", r
    if re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", t) and len(t) >= 4:
        try:
            s2 = t.replace("-", "+").replace("_", "/")
            s2 += "=" * (-len(s2) % 4)
            r = base64.b64decode(s2, validate=True).decode("utf-8")
            if _printable(r) and r != t:
                return "Base64", r
        except (ValueError, binascii.Error, UnicodeDecodeError):
            pass
    return None


def auto_decode(text, max_layers=12):
    """Tenta desembrulhar camadas de codificação uma por uma."""
    cur = text
    lines = [f"Entrada: {cur}"]
    n = 0
    for _ in range(max_layers):
        got = _try_layers(cur)
        if not got:
            break
        n += 1
        name, cur = got
        lines.append(f"\nCamada {n} — {name}:\n{cur}")
    if n == 0:
        lines.append("\nNenhuma codificação reconhecida (Base64, Hex, URL, HTML, Unicode, Binário).")
        lines.append(f"Dica — em ROT13 ficaria: {rot13(text)}")
    else:
        lines.append(f"\n✔ Resultado final ({n} camada{'s' if n > 1 else ''}):\n{cur}")
    return "\n".join(lines)


# ---------------------------------------------------------------- hashes
HASH_ALGOS = ["md5", "sha1", "sha256", "sha512", "sha3_256"]


def hashes_text(text):
    raw = text.encode("utf-8")
    rows = [(a.upper().replace("_", "-"), hashlib.new(a, raw).hexdigest()) for a in HASH_ALGOS]
    rows.append(("CRC32", f"{zlib.crc32(raw) & 0xFFFFFFFF:08x}"))
    return "\n".join(f"{k:<9} {v}" for k, v in rows)


def hmac_text(text, key, algo="sha256"):
    return hmac.new(key.encode("utf-8"), text.encode("utf-8"), algo.lower().replace("-", "")).hexdigest()


def hash_file(path, chunk=1 << 20):
    hs = {a: hashlib.new(a) for a in HASH_ALGOS}
    crc = 0
    size = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            size += len(b)
            crc = zlib.crc32(b, crc)
            for h in hs.values():
                h.update(b)
    rows = [f"Arquivo: {path}", f"Tamanho: {size:,} bytes".replace(",", "."), ""]
    rows += [f"{a.upper().replace('_', '-'):<9} {h.hexdigest()}" for a, h in hs.items()]
    rows.append(f"{'CRC32':<9} {crc & 0xFFFFFFFF:08x}")
    return "\n".join(rows)


# ---------------------------------------------------------------- identificar hash
_PREFIXES = [
    (r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt"),
    (r"^\$argon2(id|i|d)\$", "Argon2"),
    (r"^\$6\$", "sha512crypt (Linux /etc/shadow)"),
    (r"^\$5\$", "sha256crypt (Linux /etc/shadow)"),
    (r"^\$1\$", "md5crypt (Linux/Cisco antigo)"),
    (r"^\$apr1\$", "Apache MD5 (htpasswd)"),
    (r"^\$y\$", "yescrypt (Linux moderno)"),
    (r"^\$P\$|^\$H\$", "phpass (WordPress/phpBB)"),
    (r"^\$pbkdf2-sha(1|256|512)\$", "PBKDF2 (passlib)"),
    (r"^pbkdf2_sha256\$", "PBKDF2-SHA256 (Django)"),
    (r"^scrypt:|^\$scrypt\$|^\$7\$", "scrypt"),
    (r"^\*[0-9A-Fa-f]{40}$", "MySQL 4.1+/5 (SHA1 duplo)"),
    (r"^\{SSHA\}", "LDAP SSHA"),
    (r"^\{SHA\}", "LDAP SHA1 (Base64)"),
    (r"^0x0100[0-9A-Fa-f]{48}$", "MSSQL 2005"),
    (r"^0x0200[0-9A-Fa-f]{136}$", "MSSQL 2012+"),
]

_HEX_LEN = {
    8: ["CRC32", "Adler-32"],
    16: ["MySQL 3.x (antigo)", "metade de MD5", "LM (metade)"],
    32: ["MD5", "NTLM (Windows)", "MD4", "LM", "RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160", "MySQL5 (sem o *)"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s", "Keccak-256"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"],
}


def identify_hash(h):
    h = h.strip()
    if not h:
        return []
    found = [name for pat, name in _PREFIXES if re.search(pat, h)]
    if found:
        return found
    if ":" in h:
        a, b = h.split(":", 1)
        if re.fullmatch(r"[0-9a-fA-F]{32}", a) and re.fullmatch(r"[0-9a-fA-F]{32}", b):
            return ["LM:NTLM (dump do SAM/secretsdump)"]
        if re.fullmatch(r"[0-9a-fA-F]{32,128}", a):
            return [f"{t} com salt (hash:salt)" for t in identify_hash(a)]
    if re.fullmatch(r"[0-9a-fA-F]+", h):
        return list(_HEX_LEN.get(len(h), []))
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", h) and len(h) % 4 == 0:
        try:
            n = len(base64.b64decode(h))
        except (binascii.Error, ValueError):
            return []
        by = {16: "MD5", 20: "SHA-1", 32: "SHA-256", 48: "SHA-384", 64: "SHA-512"}
        if n in by:
            return [f"{by[n]} em Base64"]
    return []


def identify_report(h):
    h = h.strip()
    if not h:
        return "Cole um hash."
    types = identify_hash(h)
    cs = "hex" if re.fullmatch(r"[0-9a-fA-F]+", h) else "misto"
    head = f"Tamanho: {len(h)} caracteres · charset: {cs}\n"
    if not types:
        return head + "\nNão reconheci esse formato."
    return head + "\nProváveis tipos (do mais comum pro menos):\n" + "\n".join(f"  • {t}" for t in types)


# ---------------------------------------------------------------- JWT
def _b64url_dec(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _fmt_ts(v):
    try:
        dt = datetime.fromtimestamp(float(v), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return str(v)
    loc = dt.astimezone()
    return f"{loc:%d/%m/%Y %H:%M:%S} (local) · {dt:%d/%m/%Y %H:%M:%S} UTC"


def jwt_parse(token):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT precisa ter 3 partes separadas por ponto (header.payload.assinatura).")
    header = json.loads(_b64url_dec(parts[0]))
    payload = json.loads(_b64url_dec(parts[1]))
    return header, payload, parts


def jwt_decode(token, now=None):
    header, payload, parts = jwt_parse(token)
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    out = ["HEADER:", json.dumps(header, indent=2, ensure_ascii=False), "",
           "PAYLOAD:", json.dumps(payload, indent=2, ensure_ascii=False), "", "DATAS:"]
    labels = {"iat": "Emitido (iat)", "nbf": "Válido a partir (nbf)", "exp": "Expira (exp)"}
    any_date = False
    for k, lbl in labels.items():
        if k in payload:
            any_date = True
            out.append(f"  {lbl}: {_fmt_ts(payload[k])}")
    if not any_date:
        out.append("  (sem iat/nbf/exp)")
    out.append("")
    if isinstance(payload.get("exp"), (int, float)):
        out.append("Status: ⛔ EXPIRADO" if payload["exp"] < now else "Status: ✅ dentro da validade")
    else:
        out.append("Status: sem 'exp' — o token não expira sozinho ⚠")
    if isinstance(payload.get("nbf"), (int, float)) and payload["nbf"] > now:
        out.append("Aviso: ainda não vale (nbf no futuro).")
    alg = str(header.get("alg", "?"))
    out.append(f"Algoritmo: {alg}")
    if alg.lower() == "none":
        out.append("⚠ alg 'none': token sem assinatura — o servidor NUNCA deveria aceitar isso.")
    if not parts[2]:
        out.append("⚠ Assinatura vazia.")
    return "\n".join(out)


JWT_HS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def jwt_verify(token, secret):
    header, _payload, parts = jwt_parse(token)
    alg = str(header.get("alg", "")).upper()
    if alg not in JWT_HS:
        return False, f"Algoritmo '{header.get('alg')}' não suportado aqui (só HS256/HS384/HS512)."
    msg = f"{parts[0]}.{parts[1]}".encode("ascii")
    good = _b64url_enc(hmac.new(secret.encode("utf-8"), msg, JWT_HS[alg]).digest())
    if hmac.compare_digest(good, parts[2]):
        return True, f"✅ Assinatura VÁLIDA ({alg}) com esse segredo."
    return False, f"❌ Assinatura NÃO confere ({alg}) com esse segredo."


# ---------------------------------------------------------------- tempo
def ts_to_date(text):
    s = text.strip().replace(",", ".")
    if not s:
        return "Digite um timestamp (ex.: 1700000000)."
    v = float(s)
    unit = "segundos"
    if abs(v) >= 1e11:
        v /= 1000.0
        unit = "milissegundos"
    dt = datetime.fromtimestamp(v, tz=timezone.utc)
    loc = dt.astimezone()
    return (f"Detectado: {unit}\n\n"
            f"UTC:    {dt:%d/%m/%Y %H:%M:%S} ({dt.isoformat()})\n"
            f"Local:  {loc:%d/%m/%Y %H:%M:%S} ({loc.isoformat()})\n\n"
            f"Segundos:      {int(v)}\nMilissegundos: {int(round(v * 1000))}")


_DATE_FMTS = ["%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y",
              "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"]


def parse_date(text, utc=False):
    s = text.strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        dt = None
        for f in _DATE_FMTS:
            try:
                dt = datetime.strptime(s, f)
                break
            except ValueError:
                continue
        if dt is None:
            raise ValueError("Data não reconhecida. Use dd/mm/aaaa hh:mm:ss ou aaaa-mm-dd hh:mm:ss.")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc) if utc else dt.astimezone()
    return dt


def date_to_ts(text, utc=False):
    if not text.strip():
        return "Digite uma data (ex.: 25/12/2026 18:30:00)."
    dt = parse_date(text, utc)
    sec = dt.timestamp()
    return (f"Interpretado como: {dt.isoformat()}\n\n"
            f"Segundos:      {int(sec)}\nMilissegundos: {int(round(sec * 1000))}")


# ---------------------------------------------------------------- gerar
def gen_uuids(n=1):
    return "\n".join(str(uuid.uuid4()) for _ in range(max(1, int(n))))


def gen_token(nbytes=32, fmt="hex"):
    nbytes = max(1, int(nbytes))
    raw = secrets.token_bytes(nbytes)
    if fmt == "hex":
        return raw.hex()
    if fmt == "base64url":
        return _b64url_enc(raw)
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------- inspecionar
INVISIBLE = {
    0x200B: "ZERO WIDTH SPACE", 0x200C: "ZERO WIDTH NON-JOINER", 0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER", 0xFEFF: "BOM / ZERO WIDTH NO-BREAK SPACE", 0x00AD: "SOFT HYPHEN",
    0x200E: "LEFT-TO-RIGHT MARK", 0x200F: "RIGHT-TO-LEFT MARK", 0x202A: "LRE", 0x202B: "RLE",
    0x202C: "PDF (pop direcional)", 0x202D: "LRO", 0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI", 0x00A0: "NO-BREAK SPACE",
    0x180E: "MONGOLIAN VOWEL SEPARATOR", 0x3164: "HANGUL FILLER", 0x115F: "HANGUL CHOSEONG FILLER",
}


def _is_suspicious(ch):
    cp = ord(ch)
    if cp in INVISIBLE:
        return True
    if ch in "\n\r\t":
        return False
    cat = unicodedata.category(ch)
    return cat in ("Cf", "Cc", "Co", "Cn") or (0xE0000 <= cp <= 0xE007F)


def inspect_text(text):
    raw = text.encode("utf-8")
    non_ascii = sum(1 for c in text if ord(c) > 127)
    sus = [(i, c) for i, c in enumerate(text) if _is_suspicious(c)]
    lines = [f"Caracteres: {len(text)}", f"Bytes UTF-8: {len(raw)}",
             f"Linhas: {text.count(chr(10)) + 1 if text else 0}",
             f"Não-ASCII: {non_ascii}", f"Invisíveis/suspeitos: {len(sus)}", ""]
    if sus:
        lines.append("Achados:")
        for i, c in sus[:200]:
            cp = ord(c)
            name = INVISIBLE.get(cp) or unicodedata.name(c, "sem nome")
            lines.append(f"  posição {i}: U+{cp:04X}  {name}")
        lines.append("")
        marked = "".join(f"⟦U+{ord(c):04X}⟧" if _is_suspicious(c) else c for c in text)
        lines += ["Texto com os invisíveis destacados:", marked]
    else:
        lines.append("Nenhum caractere invisível encontrado. ✔")
    scripts = {}
    for c in text:
        if ord(c) > 127 and c.isalpha():
            sc = unicodedata.name(c, "?").split(" ")[0]
            scripts[sc] = scripts.get(sc, 0) + 1
    if scripts:
        lines += ["", "Alfabetos não-ASCII presentes (ajuda a achar homóglifos):"]
        lines += [f"  {k}: {v}" for k, v in sorted(scripts.items(), key=lambda x: -x[1])]
    return "\n".join(lines)
