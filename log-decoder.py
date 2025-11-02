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

# convert the list to a set to make word lookup faster
KW_SET = set(COMMAND_KEYWORDS)

def score_text_for_commands(text: str) -> int:
    # if empty, return 0
    if not text:
        return 0
    
    # change all to lowercase (case-insensitive)
    t = text.lower()
    
    try:
        # if string can be parse as JSON list, gather as text
        # eg.: '["id","whoami"]' → "id whoami"
        parsed = json.loads(t)
        if isinstance(parsed, list):
            t = " ".join(str(x).lower() for x in parsed)
    except Exception:
        # if not JSON, pass
        pass

    score = 0
    # check keyword one by one
    for kw in KW_SET:
        # use regex to ensure a whole-word match
        # (?<![a-z0-9]) → No letter or digit may appear immediately before the keyword
        # (?![a-z0-9]) → No letter or digit may appear immediately after the keyword
        # so "id" will not match with "userid" and similar cases
        if re.search(r'(?<![a-z0-9])' + re.escape(kw) + r'(?![a-z0-9])', t):
            score += 1 # add score if keyword found
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
    
    # --- step 1: try URL decode ---
    url = try_url_unquote(s)
    s2 = url if url and url!=s else s
    if url and url!=s:
        results.append(('url-unquote', s2, score_text_for_commands(s2)))
    
    # --- step 2: try multiple decoding method ---
    for name, fn in [
                     ('hex', try_hex), 
                     ('base64', try_base64),
                     ('base64+decompress', try_base64_and_decompress), 
                     ('rot13', try_rot13)]:
        try:
            out = fn(s2)
            if out: # if decode success
                sc = score_text_for_commands(out) # count scor (Indication of a potentially dangerous command)
                results.append((name, out, sc))
        except Exception:
            pass # if fail, continue to next method
    
    # --- step 3: try XOR single-byte (only for hex input) ---
    # (This technique is often used by malware/webshells to conceal commands)
    xor = try_xor_single_byte_hex(s2)
    if xor:
        k, out = xor # k = key xor, out = decode result
        sc = score_text_for_commands(out)
        results.append((f'single-byte-xor-key={k}', out, sc))

    # --- step 4: sort results by highest score ---
    results.sort(key=lambda x: (x[2],), reverse=True)
    return results

def choose_best_candidate(candidates):
    # If there are no candidates, there is nothing to select, return None
    if not candidates:
        return None
    
    # 1) Sort candidates by (score, text length) in descending order.
    #    - x[2] is the score (score_text_for_commands)
    #    - -len(x[1]) make candidates with longer texts prioritized
    #    - reverse=True => highest value (high score, long text) in front
    candidates_sorted = sorted(candidates, key=lambda x: (x[2], -len(x[1])), reverse=True)

    # Take the highest score from the top candidates
    top_score = candidates_sorted[0][2]

    # 2) If the highest score > 0 (there is an indication of "suspicious"), choose from them.
    if top_score > 0:
        # collect all candidates who have the same score as the highest score
        top_candidates = [c for c in candidates_sorted if c[2]==top_score]

        # From the candidates with the highest scores, select the one that most closely resembles the command text.
        def pref(c):
            text = c[1] # decoded text
            bonus = 0

            # if the text starts with '[' or '{' or contains quotes,
            # this is probably a data structure (JSON/list) or string containing the command, give bonus
            if text.startswith('[') or text.startswith('{') or '"' in text or "'" in text:
                bonus += 1

            # If there are control characters (<32) in the first 50 characters,
            # the control byte at the beginning reduces the likelihood that the decode is a human command
            # it can be a binary/garbage sign, reduce preference
            if any(ord(ch) < 32 for ch in text[:50]):
                # The -1 penalty was chosen only as a minor penalty (not to discard the total score),
                # to lower the priority of candidates that appear binary/garbage.
                bonus -= 1
            return bonus
        
        # Sort top_candidates by pref() descending (preferably at the front)
        top_candidates.sort(key=lambda x: pref(x), reverse=True)
        return top_candidates[0]

    # 3) If there are no candidates with a score > 0 (nothing clearly suspicious),
    #    use a fixed preference order based on the decoding method:
    #    (preference: base64 first, then base64+decompress, hex, etc.)
    preferred_order = ['base64',
                       'base64+decompress',
                       'hex',
                       'rot13',
                       'uuencode']
    for pref in preferred_order:
        # c[0] is assumed to be the name/decoding method
        for c in candidates:
            if c[0]==pref:
                return c # if there is a candidate with the desired method, select it
            
    # 4) If none match the preferences, return the first candidate (sorted by score)
    return candidates[0]

def decode_and_choose(encoded: str):
    candidates = multi_try_decode(encoded)
    best = choose_best_candidate(candidates)
    return candidates, best

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
    # Return True if message likely contains binary / non-printable characters.
    return any(ord(c) < 32 and c not in ("\n", "\r", "\t") for c in msg_raw)

def decode_wp_meta_from_msg(msg_raw: str) -> str:
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

    # --- finalize output ---
    if decoded_annotation:
        return decoded_annotation + rce_suffix
    else:
        return original + rce_suffix
    

def convert_csv_to_log(csv_file: str, log_file: str):
    if not os.path.exists(csv_file):
        raise FileNotFoundError(csv_file)
    
    # Calculate the total rows
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

            # Progress every 50.000 rows
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
