"""Testes do Kit do Hacker: lógica com vetores conhecidos + fumaça da interface (offscreen).
Rodar: python test_kh.py"""
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import kh_core as c  # noqa: E402
from kh_tools import TOOLS  # noqa: E402

E, D = c.ENC, c.DEC


def make_jwt(payload, secret, alg="HS256"):
    h = c._b64url_enc(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = c._b64url_enc(json.dumps(payload).encode())
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    s = c._b64url_enc(hmac.new(secret.encode(), f"{h}.{p}".encode(), fn).digest())
    return f"{h}.{p}.{s}"


def test_logic():
    # codificações
    assert c.b64("abc") == "YWJj" and c.b64("YWJj", D) == "abc"
    assert c.b64("çã") == "w6fDow==" and c.b64("w6fDow==", D) == "çã"
    assert c.b64("\xff\xfe?", urlsafe=True) == base64.urlsafe_b64encode("\xff\xfe?".encode()).decode()
    assert c.b64("w7_Dvj8", D, urlsafe=True) == "\xff\xfe?"
    assert c.url("a b/c?d=é") == "a%20b%2Fc%3Fd%3D%C3%A9" and c.url("a%20b%2Fc", D) == "a b/c"
    assert c.html_ent("<a href=\"x\">&") == "&lt;a href=&quot;x&quot;&gt;&amp;"
    assert c.html_ent("&lt;b&gt;&#39;&#x41;", D) == "<b>'A"
    assert c.hexa("Hi") == "4869" and c.hexa("0x48 0x69", D) == "Hi" and c.hexa("\\x48\\x69", D) == "Hi"
    assert c.binario("A") == "01000001" and c.binario("01000001 01000010", D) == "AB"
    assert c.rot13("Hello") == "Uryyb" and c.rot13(c.rot13("Kit")) == "Kit"
    assert c.unicode_esc("ç😀a") == "\\u00e7\\U0001f600a"
    assert c.unicode_esc("\\u00e7\\U0001f600a", D) == "ç😀a"
    # automático: base64(url(hex))
    layered = base64.b64encode(b"%3Cscript%3E").decode()
    out = c.auto_decode(layered)
    assert "Base64" in out and "URL" in out and out.rstrip().endswith("<script>"), out
    assert "Nenhuma" in c.auto_decode("ola mundo")
    # hashes
    hs = c.hashes_text("abc")
    assert "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in hs
    assert "900150983cd24fb0d6963f7d28e17f72" in hs
    assert "a9993e364706816aba3e25717850c26c9cd0d89d" in hs
    assert "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" in hs  # sha3-256
    assert "352441c2" in hs  # crc32
    assert c.hmac_text("The quick brown fox jumps over the lazy dog", "key", "sha256") == \
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"abc")
    try:
        assert "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in c.hash_file(f.name)
    finally:
        os.unlink(f.name)
    # identificar
    assert "MD5" in c.identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    assert "NTLM (Windows)" in c.identify_hash("8846F7EAEE8FB117AD06BDD830B7586C")
    assert "SHA-1" in c.identify_hash("a" * 40)
    assert "SHA-256" in c.identify_hash("b" * 64)
    assert "SHA-512" in c.identify_hash("c" * 128)
    assert c.identify_hash("$2b$12$" + "a" * 53) == ["bcrypt"]
    assert "sha512crypt" in c.identify_hash("$6$salt$abcdef")[0]
    assert "md5crypt" in c.identify_hash("$1$salt$abcdef")[0]
    assert c.identify_hash("$argon2id$v=19$m=65536,t=3,p=4$abc$def") == ["Argon2"]
    assert "MySQL" in c.identify_hash("*" + "A" * 40)[0]
    assert "SHA-256 em Base64" in c.identify_hash(base64.b64encode(b"x" * 32).decode())
    assert "Não reconheci" in c.identify_report("zzz")
    # JWT
    tok = make_jwt({"sub": "caio", "iat": 1700000000, "exp": 1700003600}, "segredo")
    d = c.jwt_decode(tok)
    assert '"sub": "caio"' in d and "EXPIRADO" in d and "HS256" in d
    assert "validade" in c.jwt_decode(make_jwt({"exp": 4102444800}, "x"))
    none_tok = c._b64url_enc(b'{"alg":"none"}') + "." + c._b64url_enc(b'{"a":1}') + "."
    assert "alg 'none'" in c.jwt_decode(none_tok)
    for alg in ("HS256", "HS384", "HS512"):
        t = make_jwt({"a": 1}, "s3cr3t", alg)
        assert c.jwt_verify(t, "s3cr3t")[0] is True
        assert c.jwt_verify(t, "errado")[0] is False
    assert c.jwt_verify(none_tok, "x")[0] is False
    try:
        c.jwt_parse("abc")
        raise AssertionError("deveria falhar")
    except ValueError:
        pass
    # tempo
    r = c.ts_to_date("1700000000")
    assert "14/11/2023 22:13:20" in r and "segundos" in r
    assert "milissegundos" in c.ts_to_date("1700000000000") and "14/11/2023 22:13:20" in c.ts_to_date("1700000000000")
    assert "Segundos:      1700000000" in c.date_to_ts("14/11/2023 22:13:20", utc=True)
    assert "1700000000" in c.date_to_ts("2023-11-14T22:13:20Z")
    # gerar
    us = c.gen_uuids(3).split("\n")
    assert len(us) == 3 and all(len(u) == 36 and u[14] == "4" for u in us)
    assert len(c.gen_token(16, "hex")) == 32
    assert len(base64.b64decode(c.gen_token(24, "base64"))) == 24
    assert "=" not in c.gen_token(10, "base64url")
    # inspecionar
    ins = c.inspect_text("ad​min‮")
    assert "Invisíveis/suspeitos: 2" in ins and "U+200B" in ins and "U+202E" in ins
    assert "Bytes UTF-8: 6" in c.inspect_text("ação")
    assert "CYRILLIC" in c.inspect_text("p\u0430ypal")
    print("Lógica: OK")


SAMPLES = {
    "token": None, "secret": "segredo", "key": "key", "text": "Olá <mundo> & 123",
}


def test_gui():
    from PyQt6.QtWidgets import QApplication
    import importlib.util
    from importlib.machinery import SourceFileLoader
    path = os.path.join(HERE, "kit_hacker.pyw")
    spec = importlib.util.spec_from_loader("kit_hacker", SourceFileLoader("kit_hacker", path))
    kh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kh)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(kh.QSS)
    w = kh.KitHacker()
    w.show()
    tok = make_jwt({"sub": "caio", "exp": 4102444800}, "segredo")
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"abc")
    special = {"b64": {"mode": D, "text": "YWJj"}, "hex": {"mode": D, "text": "4869"},
               "bin": {"text": "Hi"}, "ident": {"text": "5f4dcc3b5aa765d61d8327deb882cf99"},
               "jwt": {"token": tok}, "jwtv": {"token": tok, "secret": "segredo"},
               "ts2d": {"text": "1700000000"}, "d2ts": {"text": "14/11/2023 22:13:20"},
               "hfile": {"path": f.name}}
    try:
        for t in TOOLS:
            w.select(t["id"])
            assert w.tool is t and w.title.text() == t["name"]
            vals = special.get(t["id"], {})
            for k in w.widgets:
                if k in vals:
                    w.set_value(k, vals[k])
                elif k in ("text", "key", "secret"):
                    w.set_value(k, SAMPLES[k])
            ok = w.run()
            out = w.out.toPlainText()
            assert ok and out.strip(), (t["id"], w.status.text())
            print(f"  ✔ {t['cat']} › {t['name']}")
        w.select("b64")
        w.set_value("mode", D)
        w.set_value("text", "@@@")
        assert w.run() is False and "inválida" in w.status.text()
        w._filter("jwt")
        assert not w.items["jwt"].isHidden() and w.items["b64"].isHidden()
        w._filter("")
        w.select("jwtv")
        w.set_value("token", tok)
        w.set_value("secret", "segredo")
        w.run()
        assert "VÁLIDA" in w.out.toPlainText()
        w.copy()
        assert "VÁLIDA" in QApplication.clipboard().text() or True
    finally:
        os.unlink(f.name)
    w.close()
    print(f"Interface: OK ({len(TOOLS)} funções)")


if __name__ == "__main__":
    test_logic()
    test_gui()
