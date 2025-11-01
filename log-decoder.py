#!/usr/bin/env python3
# webshell-decode-v4.py (with CSV->log conversion)
# Enhanced decoder v4: chooses best decode candidate by matching known command keywords (scored).
# Adds CSV -> annotated log conversion compatible with previous v3 workflow.
import sys, urllib.parse, base64, binascii, codecs, zlib, gzip, re, json, csv, os
from typing import Optional, Tuple, List

# command keyword buckets (flattened list for scoring)
COMMAND_KEYWORDS = [
    "id","whoami","uname","date","cal","uptime","who","w","last","finger","lsb_release","clear",
    "netstat","ip","ifconfig","ss","netcat",
    "ls","find","chmod","chown","rm","mv","echo","base64","dir","cp","cd",
    "cat","head","tail","less","more","strings","last",
    "wget","curl","fetch",
    "ps","top","tmux","screen",
    "mysql","psql","pgsql","mongo","redis-cli",
    "tar","zip","unzip","7z","rar",
    "bash","sh",".sh",
    "perl","python","python3","php","ruby","lua","gcc",
    "nc","socat","ssh",
    "nmap","masscan",
    "tcpdump","wireshark","tshark","ettercap","dsniff","iptables","ufw","firewalld",
    "hydra","medusa","john","hashcat",
    "gdb","strace","ltrace",
    "systemctl","service","init.d","rc.d","pwd","dpkg","ps","ss"
    "docker","kubectl","helm",
    "git","svn","hg"
]
# Build regex: longest-first, escaped
_escaped = sorted([re.escape(k) for k in COMMAND_KEYWORDS], key=len, reverse=True)
# For decoded values (spaces are real): ^(?:keyword)\s
CMD_START_DECODED = re.compile(r'^(?:' + r'|'.join(_escaped) + r')\s', flags=re.IGNORECASE)
# For raw values (may contain + or %20 between keyword and args)
CMD_START_RAW = re.compile(r'^(?:' + r'|'.join(_escaped) + r')(?:(?:\+)|(?:%20)|(?:\s))', flags=re.IGNORECASE)

# Ubah list ke set agar pencarian kata lebih cepat (O(1) lookup).
KW_SET = set(COMMAND_KEYWORDS)

def score_text_for_commands(text: str) -> int:
    # Jika teks kosong, langsung kembalikan skor 0
    if not text:
        return 0
    
    # Ubah semua huruf ke lowercase agar pencarian tidak case-sensitive
    t = text.lower()
    
    try:
        # Jika string bisa diparse sebagai JSON list, gabungkan isinya menjadi teks
        # Contoh: '["id","whoami"]' → "id whoami"
        parsed = json.loads(t)
        if isinstance(parsed, list):
            t = " ".join(str(x).lower() for x in parsed)
    except Exception:
        # Kalau gagal parse JSON, abaikan saja
        pass

    score = 0
    # Cek satu per satu keyword
    for kw in KW_SET:
        # Gunakan regex untuk memastikan cocok sebagai kata utuh
        # (?<![a-z0-9]) → sebelum keyword tidak boleh huruf/angka
        # (?![a-z0-9]) → setelah keyword tidak boleh huruf/angka
        # Dengan begitu "id" tidak akan match di "userid"
        if re.search(r'(?<![a-z0-9])' + re.escape(kw) + r'(?![a-z0-9])', t):
            score += 1 # Tambah skor jika keyword ditemukan
    return score

def try_url_unquote(s: str) -> Optional[str]:
    # example
    # "Hello%20World " → "Hello World "
    # "user%40example.com" → "user@example.com"
    try:
        out = urllib.parse.unquote_plus(s)
        return out
    except Exception:
        return None

def try_hex(s: str) -> Optional[str]:
    # example:
    # encoode payload: "2f62696e2f7368" → "/bin/sh"
    # "746573742e706870" → "test.php"
    try:
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s)%2==0 and len(s)>=8:
            return bytes.fromhex(s).decode('utf-8', errors='replace')
    except Exception:
        pass
    return None

def try_base64(s: str) -> Optional[str]:
    # example:
    # "aWQ=" → "id"
    # "d2hvYW1p" → "whoami"
    try:
        missing = len(s) % 4
        if missing:
            s = s + ("=" * (4-missing))
        raw = base64.b64decode(s, validate=False)
        try:
            return raw.decode('utf-8', errors='replace')
        except Exception:
            return raw.decode('latin-1', errors='replace')
    except Exception:
        return None

def try_base64_and_decompress(s: str) -> Optional[str]:
    # example:
    # first Base64, then zlib : "eJyrVkrLz1eyUkpKLFKqBQAe4QbL" → "rm -rf /tmp"
    # gzip: "H4sIAAAAAAAAA/NIzcnJVwjPL8pJAQAA//8DAK6+9U0NAAAA" → "id"
    try:
        missing = len(s) % 4
        if missing:
            s = s + ("=" * (4-missing))
        raw = base64.b64decode(s, validate=False)
        try:
            return gzip.decompress(raw).decode('utf-8', errors='replace')
        except Exception:
            pass
        try:
            return zlib.decompress(raw, -zlib.MAX_WBITS).decode('utf-8', errors='replace')
        except Exception:
            pass
    except Exception:
        pass
    return None

def try_rot13(s: str) -> Optional[str]:
    # example:
    # "cevag('Uryyb Jbeyq')" → "print('Hello World')"
    try:
        out = codecs.decode(s, 'rot_13')
        return out
    except Exception:
        return None

def try_xor_single_byte_hex(s: str) -> Optional[Tuple[int,str]]:
    # example:
    # "3f262d2623" → XOR key=0x5a → "?&-&&#"
    # "070f010a010c" → XOR key=0x6f → "id"
    try:
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s)%2==0:
            ct = bytes.fromhex(s)
            for k in range(1,256):
                pt = bytes([b ^ k for b in ct])
                if b"<?php" in pt or b"eval(" in pt or b"system" in pt or b"exec" in pt:
                    return (k, pt.decode('utf-8', errors='replace'))
    except Exception:
        pass
    return None

def multi_try_decode(s: str) -> List[Tuple[str,str,int]]:
    results = []
    if not s:
        return results
    
    # --- tahap 1: coba URL decode ---
    url = try_url_unquote(s)
    s2 = url if url and url!=s else s
    if url and url!=s:
        results.append(('url-unquote', s2, score_text_for_commands(s2)))
    
    # --- tahap 2: coba berbagai metode decoding ---
    for name, fn in [
                     ('hex', try_hex), 
                     ('base64', try_base64),
                     ('base64+decompress', try_base64_and_decompress), 
                     ('rot13', try_rot13)]:
        try:
            out = fn(s2)
            if out: # kalau decode berhasil
                sc = score_text_for_commands(out) # hitung skor (indikasi command berbahaya)
                results.append((name, out, sc))
        except Exception:
            pass # kalau gagal decode, lanjut metode berikutnya
    
    # --- tahap 3: coba XOR single-byte (hanya untuk hex input) ---
    # (teknik sering dipakai malware/webshell untuk menyembunyikan perintah)
    xor = try_xor_single_byte_hex(s2)
    if xor:
        k, out = xor # k = key xor, out = hasil decode
        sc = score_text_for_commands(out)
        results.append((f'single-byte-xor-key={k}', out, sc))

    # --- tahap 4: sortir hasil berdasarkan skor tertinggi ---
    results.sort(key=lambda x: (x[2],), reverse=True)
    return results

def choose_best_candidate(candidates):
    # Jika tidak ada kandidat, tidak ada yang bisa dipilih → kembalikan None
    if not candidates:
        return None
    
    # 1) Urutkan kandidat berdasarkan (skor, panjang teks) secara menurun.
    #    - x[2] adalah skor (score_text_for_commands)
    #    - -len(x[1]) membuat kandidat yang teksnya lebih panjang diprioritaskan
    #    - reverse=True => nilai terbesar (skor tinggi, teks panjang) di depan
    candidates_sorted = sorted(candidates, key=lambda x: (x[2], -len(x[1])), reverse=True)

    # Ambil skor tertinggi dari kandidat teratas
    top_score = candidates_sorted[0][2]

    # 2) Jika skor tertinggi > 0 (ada indikasi "mencurigakan"), pilih dari mereka
    if top_score > 0:
        # kumpulkan semua kandidat yang punya skor sama dengan skor tertinggi
        top_candidates = [c for c in candidates_sorted if c[2]==top_score]

        # dari kandidat dengan skor tertinggi, pilih yang paling miri teks perintah
        def pref(c):
            text = c[1] # teks hasil decoding
            bonus = 0

            # jika teks dimulai dengan '[' atau '{' atau mengandung kutipan,
            # kemungkinan ini struktur data (JSON/list) atau string berisi perintah → beri bonus
            if text.startswith('[') or text.startswith('{') or '"' in text or "'" in text:
                bonus += 1

            # jika dalam 50 karakter pertama ada karakter kontrol (< 32),
            # byte kontrol di awal mengurangi kemungkinan bahwa decode itu adalah perintah manusia
            # itu bisa tanda binary/garbage → kurangi preferensi
            if any(ord(ch) < 32 for ch in text[:50]):
                # Penalti -1 dipilih cuma sebagai penalty ringan (bukan membuang total skor), 
                # untuk menurunkan prioritas kandidat yang terlihat biner/garbage.
                bonus -= 1
            return bonus
        
        # Urutkan top_candidates berdasarkan pref() menurun (lebih disukai di depan)
        top_candidates.sort(key=lambda x: pref(x), reverse=True)
        return top_candidates[0]

    # 3) Jika tidak ada kandidat dengan skor > 0 (tidak ada yang jelas mencurigakan),
    #    gunakan urutan preferensi tetap berdasarkan metode decoding:
    #    (preferensi: base64 dulu, lalu base64+decompress, hex, dll.)
    preferred_order = ['base64',
                       'base64+decompress',
                       'hex',
                    #    'ascii85',
                    #    'base32',
                       'rot13',
                       'uuencode']
    for pref in preferred_order:
        # c[0] diasumsikan adalah nama/metode decoding
        for c in candidates:
            if c[0]==pref:
                return c # jika ada kandidat dengan metode yg diinginkan, pilih itu
            
    # 4) Jika tidak ada yang cocok dengan preferensi, kembalikan kandidat pertama (terurut berdasarkan skor)
    return candidates[0]

def decode_and_choose(encoded: str):
    candidates = multi_try_decode(encoded)
    best = choose_best_candidate(candidates)
    return candidates, best

# def detect_sqli_in_url(msg_raw: str) -> Optional[str]:
#     """
#     Detect simple SQL injection probes in the request URI/query string.
#     Returns a short extracted suspicious fragment (decoded) or None.
#     """
#     try:
#         # try to extract the request path/query from the message (common pattern: http_request: GET <path> HTTP/1.1)
#         m = re.search(r'http_request:\s*(?:GET|POST|PUT|DELETE|HEAD)\s+([^ ]+)', msg_raw, flags=re.IGNORECASE)
#         if not m:
#             # fallback: try to locate the first '?...' occurrence
#             m2 = re.search(r'(/[^?\s]*\?[^ "]+)', msg_raw)
#             if m2:
#                 uri = m2.group(1)
#             else:
#                 return None
#         else:
#             uri = m.group(1)
#         # Replace ~XX style to %XX (some logs use ~ as percent marker), then URL-decode
#         uri = uri.replace('~', '%')
#         try:
#             uri_dec = urllib.parse.unquote_plus(uri)
#         except Exception:
#             uri_dec = uri
#         # Only inspect the query part after ?
#         q = uri_dec.split('?',1)[1] if '?' in uri_dec else uri_dec
#         q_low = q.lower()

#         # Common SQLi indicators (short list). If matched, return the suspicious decoded fragment.
#         patterns = [
#             r"(?i)\bunion\b\s+\ball\b\s+\bselect\b",   # union all select
#             r"(?i)\bunion\b\s+\bselect\b",             # union select
#             r"(?i)\bselect\b.+\bfrom\b",                # select ... from ...
#             r"(?i)@@version\b",                         # mysql version variable
#             r"(?i)\binformation_schema\b",              # information_schema
#             r"(?i)\bbenchmark\s*\(",                    # benchmark( ) often used in time-based sqli
#             r"(?i)\bsleep\s*\(",                        # sleep()
#             # r"(?i)--\s*$",                              # trailing SQL comment
#             r"(?i)%27\s+or\s+%271%27=%271",             # encoded ' OR '1'='1' pattern (percent-encoded)
#             r"(?i)or\s+1=1",                            # tautology
#             r"(?i)concat\(",                            # concat used in injections
#             r"(?i)information_schema\.tables",          # information_schema.tables
#             r"(?i)union.+select.+@@version",            # union select @@version
#             r"(?i)'\s*or\s*'1'='1",                     # common tautology
#             r'(?i)"\s*or\s*"1"="1'
#         ]
#         for pat in patterns:
#             if re.search(pat, q_low):
#                 # return a normalized snippet (original decoded query)
#                 snippet = q
#                 # truncate snippet to reasonable length
#                 if len(snippet) > 200:
#                     snippet = snippet[:200] + "..."
#                 return snippet
#         return None
#     except Exception:
#         return None

def split_shell_like(snippet: str) -> List[str]:
    """Split snippet into shell-like fragments (separator ;, &&, ||, |, newline or encoded forms)."""
    if not snippet:
        return []
    s = snippet
    s = s.replace('%3B', ';').replace('%3b', ';')
    s = s.replace('%0A', '\n').replace('%0a', '\n').replace('%0D', '\n').replace('%0d', '\n')
    s = s.replace('%26%26', ' && ')
    s = s.replace('%7C', '|').replace('%7c', '|')
    s = re.sub(r'\s+', ' ', s).strip()
    parts = re.split(r'\s*(?:;|&&|\|\||\|)\s*|\n', s)
    return [p.strip() for p in parts if p and p.strip()]

def detect_rce_query_simple(msg_raw: str) -> Optional[Tuple[str, List[str]]]:
    """
    Simple rule:
    - If there is any query (any URI containing '?'),
      and any parameter value starts with a COMMAND_KEYWORD followed by whitespace (space/+/%20),
      then return (decoded_query_snippet, list_of_command_fragments).
    - Otherwise return None.
    """
    try:
        # find the first URI-like substring that contains '?'
        m = re.search(r'http_request:\s*(?:GET|POST|PUT|DELETE|HEAD)\s+([^ ]*)', msg_raw, flags=re.IGNORECASE)
        raw_uri = m.group(1) if m else None
        if not raw_uri:
            # fallback: any substring like /path?query
            m2 = re.search(r'(/[^\s"\']*\?[^\s"\']*)', msg_raw)
            raw_uri = m2.group(1) if m2 else None
        if not raw_uri or '?' not in raw_uri:
            return None

        # normalize custom tilde-escape if used in your dataset
        raw_uri = raw_uri.replace('~', '%')

        parsed = urllib.parse.urlparse(raw_uri)
        query = parsed.query or ""
        if not query:
            return None

        qs = urllib.parse.parse_qs(query, keep_blank_values=True)

        found_cmds: List[str] = []
        for key, vals in qs.items():
            for raw_val in vals:
                # raw_val is percent-decoded by parse_qs, but the original raw may have +/%20 encoded forms
                # Check both raw and decoded forms:
                decoded_val = urllib.parse.unquote_plus(raw_val).strip()
                # check decoded first (most common)
                if CMD_START_DECODED.match(decoded_val):
                    # split into commands (handles multiple commands)
                    frags = split_shell_like(decoded_val)
                    found_cmds.extend(frags if frags else [decoded_val])
                else:
                    # check raw (in case parse_qs left + or %20 somehow). We'll test raw string for + or %20 separators
                    # For safety ensure raw_val is str
                    if isinstance(raw_val, str) and CMD_START_RAW.match(raw_val):
                        # decode then split
                        frags = split_shell_like(urllib.parse.unquote_plus(raw_val))
                        found_cmds.extend(frags if frags else [urllib.parse.unquote_plus(raw_val)])

        if not found_cmds:
            return None

        # dedupe while preserving order
        seen = set()
        deduped = []
        for c in found_cmds:
            if c not in seen:
                seen.add(c)
                deduped.append(c)

        # snippet: the full decoded query string (for logging/DECODED field)
        snippet = urllib.parse.unquote_plus(query)
        return (snippet, deduped)
    except Exception:
        return None

def is_binary_like(msg_raw: str) -> bool:
    """
    Return True if message likely contains binary / non-printable characters.
    """
    return any(ord(c) < 32 and c not in ("\n", "\r", "\t") for c in msg_raw)

def decode_wp_meta_from_msg(msg_raw: str) -> str:
    """
    - Jika user_agent terdeteksi tool/script -> lakukan decoding wp_meta (seperti sebelumnya)
    - TETAPI selalu jalankan detect_sqli_in_url() untuk menambahkan [SQLi: "..."] bila terdeteksi,
      terlepas dari user_agent.
    """
    original = msg_raw

    # --- existing decode behavior (only for suspicious user agents) ---
    decoded_annotation = None
    try:
        user_agent = msg_raw.split("user_agent: ")[1].lower()
    except Exception:
        user_agent = ""

    bad_agents = ["python", "perl", "postman", "curl", "wget", "go-http-client", "java", "shell", "httpclient"]
    matches = [a for a in bad_agents if a in user_agent]
    if matches:
        # try to decode first param-like value as before
        m = re.search(r"[?&]([^=\s]+)=([^&\s]+)", msg_raw)
        if m:
            param_name = m.group(1)
            encoded = m.group(2)
            candidates, best = decode_and_choose(encoded)
            if best:
                best_text = best[1]
                for kw in KW_SET:
                    if re.search(r'(?<![a-z0-9])' + re.escape(kw) + r'(?![a-z0-9])', best_text):
                # if(is_binary_like(best_text)==False):
                        annex = " | ".join([f"{meth} => {out[:200].replace(chr(10),' ')}" for meth, out, sc in candidates])
                        decoded_annotation = f"{original} [DECODED: {best_text}] [ALL_TRIES: {annex}]"
            else:
                annex = " | ".join([f"{meth} => {out[:200].replace(chr(10),' ')}" for meth, out, sc in candidates])
                if annex:
                    decoded_annotation = f"{original} [DECODE FAILED: tried multi methods] [ALL_TRIES: {annex}]"
                else:
                    decoded_annotation = f"{original} [DECODE FAILED: no candidates]"
    # if not suspicious UA, leave decoded_annotation = None (we will use original)

    # --- run SQLi di raw message ---
    # sqli = detect_sqli_in_url(original)
    # if sqli:
    #     sqli_suffix = f' [SQLi: "{sqli}"]'
    # else:
    #     sqli_suffix = ""
    
    # --- run RCE detection di raw message ---
    rce = detect_rce_query_simple(original)
    if rce:
        snippet, cmd_list = rce
        # format rasa log:
        cmds_formatted = ' | '.join([f'"{c}"' for c in cmd_list])
        rce_suffix = f' [RCE: "{snippet}"]'
        # if cmds_formatted:
        #     rce_suffix += f' [RCE_CMDS: {cmds_formatted}]'
    else:
        rce_suffix = ""

    # --- susun output ---
    # if decoded_annotation:
    #     return decoded_annotation + sqli_suffix + rce_suffix
    # else:
    #     return original + sqli_suffix + rce_suffix
    # if decoded_annotation:
    #     return decoded_annotation
    # else:
    #     return original
    if decoded_annotation:
        return decoded_annotation + rce_suffix
    else:
        return original + rce_suffix
    

def convert_csv_to_log(csv_file: str, log_file: str):
    if not os.path.exists(csv_file):
        raise FileNotFoundError(csv_file)
    
    # Hitung total baris terlebih dahulu
    with open(csv_file, newline='', encoding="utf-8", errors='replace') as f:
        total_lines = sum(1 for _ in f)
    print(f"Total lines in {csv_file}: {total_lines}")

    processed = 0
    with open(csv_file, newline='', encoding="utf-8", errors='replace') as f, open(log_file, "w", encoding="utf-8") as out:
        reader = csv.reader(f)
        for row in reader:
            processed += 1
            try:
                # Best-effort: many plaso CSV have timestamp and time columns; adapt if different
                # Try to find a timestamp-like column; fallback to first col
                ts = row[0]
                # Some CSV rows store datetime in single field like '01/18/2022 12:38:04'
                # Try common patterns; else reuse existing ts
                import datetime as _dt
                iso = None
                try:
                    iso = _dt.datetime.strptime(ts, "%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S+00:00")
                except Exception:
                    # try split date/time in two cols
                    if len(row) > 1:
                        try:
                            iso = _dt.datetime.strptime(row[0] + " " + row[1], "%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S+00:00")
                        except Exception:
                            iso = ts
                    else:
                        iso = ts
                # parser and file path columns heuristics (adapt to user's CSV layout)
                parser = row[15] if len(row) > 15 else "text/apache_access"
                file = row[12] if len(row) > 12 else "OS:unknown"
                msg = row[10] if len(row) > 10 else ",".join(row)
                msg = decode_wp_meta_from_msg(msg)
                out.write(f"{iso} {parser} {file} {msg}\n")
            except Exception:
                continue

            # Progress tiap 50.000 baris
            if processed % 50000 == 0:
                print(f"Processed {processed}/{total_lines} lines ({processed/total_lines:.2%})")

    print(f"Conversion finished: {processed}/{total_lines} lines processed.")

def main():
    import argparse
    p = argparse.ArgumentParser(description="webshell-decode-v4 with CSV->log conversion")
    p.add_argument("--csv", help="input CSV file (plaso-result.csv)", default=None)
    p.add_argument("--out", help="output log file", default="data/convert-result-v4.log")
    p.add_argument("--single", help="try single payload", default=None)
    args = p.parse_args()
    if args.single:
        enc = args.single
        cands, best = decode_and_choose(enc)
        print("Input:", enc)
        print("All candidates:")
        for m,t,s in cands:
            print(f"- {m} (score={s}): {t[:200]!r}")
        print("\nBest candidate:")
        if best:
            print(f"{best[0]} (score={best[2]}): {best[1]!r}")
        else:
            print("No candidate found.")
        return
    if args.csv:
        try:
            convert_csv_to_log(args.csv, args.out)
            print(f"Converted {args.csv} -> {args.out}")
        except FileNotFoundError:
            print(f"CSV file not found: {args.csv}", file=sys.stderr)
            sys.exit(2)
        except Exception as e:
            print("Error converting CSV:", e, file=sys.stderr)
            sys.exit(3)
    else:
        print("Nothing to do. Use --csv <file> to convert or --single <payload> to test.")

if __name__ == "__main__":
    main()
