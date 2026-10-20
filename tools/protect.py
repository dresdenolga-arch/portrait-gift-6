#!/usr/bin/env python3
"""Шифрует содержимое сайта паролем.

  python3 tools/protect.py encrypt ПАРОЛЬ   # _source/index.html -> index.html
  python3 tools/protect.py decrypt ПАРОЛЬ   # index.html -> _source/index.html

Открытый исходник хранится в _source/ (не попадает в git). В репозиторий
коммитится только зашифрованный index.html. Шифрование: PBKDF2-SHA256 +
AES-256-GCM, расшифровка в браузере через WebCrypto.
"""
import base64, os, re, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "_source" / "index.html"
OUT = ROOT / "index.html"
ITER = 310000


def key(password, salt):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(password.encode())


LOCK = """<style>
#lock{min-height:100vh;display:grid;place-items:center;padding:24px;background:#faf7f0}
#lock form{width:min(380px,100%);text-align:center}
#lock h1{font-size:clamp(40px,11vw,60px);margin:10px 0 26px}
#lock input{width:100%;font:18px Manrope,Arial,sans-serif;padding:14px 18px;border:1px solid #d9cfbb;border-radius:40px;background:#fffdf8;color:#353a23;text-align:center;outline:none}
#lock input:focus{border-color:#a78042}
#lock button{margin-top:14px;width:100%;border:0;border-radius:40px;background:#353a23;color:#fff;padding:14px;font:700 16px Manrope,Arial,sans-serif;cursor:pointer}
#lock .err{color:#a14a3b;font-size:15px;min-height:24px;margin:12px 0 0}
</style>
<div id="lock"><form autocomplete="off">
<div class="eyebrow">Личный подарок</div>
<h1>__NAME__</h1>
<input id="pw" type="password" inputmode="numeric" placeholder="Введите пароль" aria-label="Пароль" autofocus required>
<button type="submit">Открыть</button>
<p class="err" id="err" role="alert"></p>
</form></div>
<script id="payload" type="application/octet-stream">__PAYLOAD__</script>
<script>(function(){
addEventListener('beforeinstallprompt',function(e){e.preventDefault();window.__bip=e});
var K='gift-pw',f=document.querySelector('#lock form'),pw=document.getElementById('pw'),err=document.getElementById('err');
var raw=Uint8Array.from(atob(document.getElementById('payload').textContent.trim()),function(c){return c.charCodeAt(0)});
function unlock(p){var e=new TextEncoder();
return crypto.subtle.importKey('raw',e.encode(p),'PBKDF2',false,['deriveKey']).then(function(b){
return crypto.subtle.deriveKey({name:'PBKDF2',salt:raw.slice(0,16),iterations:__ITER__,hash:'SHA-256'},b,{name:'AES-GCM',length:256},false,['decrypt'])}).then(function(k){
return crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(16,28)},k,raw.slice(28))}).then(function(d){
document.body.innerHTML=new TextDecoder().decode(d);
document.body.querySelectorAll('script').forEach(function(o){var s=document.createElement('script');s.textContent=o.textContent;o.replaceWith(s)});
if(location.hash){var t=document.querySelector(location.hash);if(t){var dd=t.querySelector('details');if(dd)dd.open=true;t.scrollIntoView()}}
try{localStorage.setItem(K,p)}catch(x){}})}
f.addEventListener('submit',function(e){e.preventDefault();err.textContent='';
unlock(pw.value).catch(function(){err.textContent='Неверный пароль';pw.select()})});
var saved=null;try{saved=localStorage.getItem(K)}catch(x){}
if(saved)unlock(saved).catch(function(){try{localStorage.removeItem(K)}catch(x){}});
})();</script>"""


def encrypt(password):
    src = SRC.read_text(encoding="utf-8")
    m = re.search(r"(?s)^(.*<body[^>]*>)(.*)(</body>.*)$", src)
    head, body, tail = m.groups()
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(key(password, salt)).encrypt(iv, body.encode("utf-8"), None)
    payload = base64.b64encode(salt + iv + ct).decode()
    name = re.search(r"<title>\s*([^<·]+?)\s*(?:·|</title>)", head).group(1)
    lock = LOCK.replace("__PAYLOAD__", payload).replace("__ITER__", str(ITER)).replace("__NAME__", name)
    OUT.write_text(head + "\n<!-- protected -->\n" + lock + "\n" + tail, encoding="utf-8", newline="\n")
    print(f"index.html зашифрован ({len(body)} символов содержимого)")


def decrypt(password):
    out = OUT.read_text(encoding="utf-8")
    raw = base64.b64decode(re.search(r'id="payload"[^>]*>([^<]+)<', out).group(1))
    body = AESGCM(key(password, raw[:16])).decrypt(raw[16:28], raw[28:], None).decode("utf-8")
    m = re.search(r"(?s)^(.*<body[^>]*>)\n<!-- protected -->.*?(</body>.*)$", out)
    SRC.parent.mkdir(exist_ok=True)
    SRC.write_text(m.group(1) + body + m.group(2), encoding="utf-8", newline="\n")
    print("Исходник восстановлен в _source/index.html")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("encrypt", "decrypt"):
        sys.exit(__doc__)
    (encrypt if sys.argv[1] == "encrypt" else decrypt)(sys.argv[2])
