#!/usr/bin/env python3
"""
github_enrich.py — pull raw content for every GitHub hit in attack_graph JSON
output and extract credential-like lines.

Usage:
    python3 github_enrich.py results.json [--token ghp_...]
    cat results.json | python3 github_enrich.py - [--token ghp_...]
"""

import sys, json, re, argparse, time, urllib.request, urllib.error, base64

SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'<>{},;]{6,})', 'password'),
    (r'(?i)(secret|secret_key|app_secret)\s*[=:]\s*["\']?([^\s"\'<>{},;]{8,})', 'secret'),
    (r'(?i)(api[_\-]?key|apikey|api[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9\-_.]{12,})', 'api_key'),
    (r'(?i)(access[_\-]?token|auth[_\-]?token|bearer)\s*[=:]\s*["\']?([A-Za-z0-9\-_.]{16,})', 'token'),
    (r'(?i)(aws[_\-]?access[_\-]?key[_\-]?id)\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})', 'aws_key_id'),
    (r'(?i)(aws[_\-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{32,})', 'aws_secret'),
    (r'AKIA[A-Z0-9]{16}', 'aws_key_id_bare'),
    (r'(?i)(database[_\-]?url|db[_\-]?url|connection[_\-]?string)\s*[=:]\s*["\']?([^\s"\'<>]{12,})', 'db_url'),
    (r'(?i)(private[_\-]?key|ssh[_\-]?key)\s*[=:]\s*["\']?([^\s"\'<>{},;]{16,})', 'private_key'),
    (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', 'private_key_pem'),
    (r'(?i)(client[_\-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9\-_.~]{16,})', 'oauth_secret'),
    (r'(?i)(smtp[_\-]?password|mail[_\-]?password|email[_\-]?password)\s*[=:]\s*["\']?([^\s"\'<>]{6,})', 'smtp_password'),
    (r'ghp_[A-Za-z0-9]{36}', 'github_pat'),
    (r'ghs_[A-Za-z0-9]{36}', 'github_app_token'),
    (r'sk-[A-Za-z0-9]{48}', 'openai_key'),
    (r'(?i)(twilio[_\-]?(?:auth[_\-]?)?token)\s*[=:]\s*["\']?([a-z0-9]{32})', 'twilio_token'),
    (r'(?i)(stripe[_\-]?(?:secret|sk)[_\-]?(?:key|live|test))\s*[=:]\s*["\']?(sk_(?:live|test)_[A-Za-z0-9]{24,})', 'stripe_key'),
    (r'sk_(?:live|test)_[A-Za-z0-9]{24,}', 'stripe_key_bare'),
    (r'(?i)(sendgrid[_\-]?(?:api[_\-]?)?key)\s*[=:]\s*["\']?(SG\.[A-Za-z0-9._-]{22,})', 'sendgrid_key'),
    (r'SG\.[A-Za-z0-9._-]{22,}', 'sendgrid_key_bare'),
    (r'(?i)(slack[_\-]?(?:token|webhook))\s*[=:]\s*["\']?((xox[baprs]-[A-Za-z0-9\-]{10,})|(https://hooks\.slack\.com/[^\s"\']+))', 'slack_token'),
    (r'xox[baprs]-[A-Za-z0-9\-]{10,}', 'slack_token_bare'),
]

BORING_LINES = re.compile(
    r'^\s*(?:#|//|<!--|/\*|\*|import |from |require|module\.exports|'
    r'class |def |function |var |let |const (?!.*=)|return |if |else|'
    r'package |using |namespace |@|\}|\{)\s',
    re.IGNORECASE
)

def fetch_raw(html_url: str, token: str) -> str | None:
    """Convert GitHub blob URL → raw.githubusercontent.com and fetch."""
    raw_url = (html_url
               .replace('github.com', 'raw.githubusercontent.com')
               .replace('/blob/', '/'))
    headers = {'User-Agent': 'github-enrich/1.0'}
    if token:
        headers['Authorization'] = f'token {token}'
    try:
        req = urllib.request.Request(raw_url, headers=headers)
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.read(200_000).decode(errors='replace')
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return None
    except Exception:
        return None


def extract_secrets(content: str) -> list[dict]:
    hits = []
    seen = set()
    for lineno, line in enumerate(content.splitlines(), 1):
        if len(line) > 500:
            continue
        for pattern, kind in SECRET_PATTERNS:
            m = re.search(pattern, line)
            if not m:
                continue
            value = m.group(0) if m.lastindex is None else (m.group(2) if m.lastindex >= 2 else m.group(1))
            key = (kind, value[:60])
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                'line': lineno,
                'kind': kind,
                'value': value[:120],
                'context': line.strip()[:160],
            })
    return hits


def enrich(data: list[dict], token: str) -> list[dict]:
    results = []
    for entry in data:
        target = entry.get('target', 'unknown')
        gh_hits = entry.get('github_hits') or []
        enriched_hits = []
        for hit in gh_hits:
            url = hit.get('url', '')
            if not url:
                continue
            print(f'  fetching {url[:90]}', file=sys.stderr)
            content = fetch_raw(url, token)
            time.sleep(0.4)
            if content is None:
                enriched_hits.append({**hit, 'raw_fetch': 'failed', 'secrets': []})
                continue
            secrets = extract_secrets(content)
            enriched_hits.append({
                **hit,
                'raw_fetch': 'ok',
                'lines': content.count('\n'),
                'secrets': secrets,
            })
        results.append({
            'target': target,
            'generated': entry.get('generated', ''),
            'github_hits': enriched_hits,
        })
    return results


def print_report(results: list[dict]):
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    GREEN  = '\033[92m'
    CYAN   = '\033[96m'
    RESET  = '\033[0m'
    BOLD   = '\033[1m'

    for entry in results:
        target = entry['target']
        hits = entry['github_hits']
        secret_count = sum(len(h.get('secrets', [])) for h in hits)
        color = RED if secret_count > 0 else CYAN
        print(f'\n{BOLD}{color}[{target}]{RESET}  github_hits={len(hits)}  secrets_found={secret_count}')

        for hit in hits:
            url = hit.get('url', '')
            fetch = hit.get('raw_fetch', '?')
            secrets = hit.get('secrets', [])
            status = f'{RED}SECRETS({len(secrets)}){RESET}' if secrets else f'{GREEN}clean{RESET}'
            fetch_color = GREEN if fetch == 'ok' else YELLOW
            print(f'  {fetch_color}{fetch}{RESET}  {status}  {url[:100]}')
            for s in secrets:
                print(f'    {BOLD}{RED}[{s["kind"]}]{RESET} line {s["line"]}')
                print(f'      value:   {s["value"]}')
                print(f'      context: {s["context"][:140]}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', nargs='?', default='-',
                    help='attack_graph JSON file (or - for stdin)')
    ap.add_argument('--token', default='',
                    help='GitHub PAT for higher rate limits')
    ap.add_argument('--json-out', metavar='FILE',
                    help='also write enriched JSON to this file')
    args = ap.parse_args()

    if args.input == '-':
        raw = sys.stdin.read()
    else:
        with open(args.input) as f:
            raw = f.read()

    data = json.loads(raw)
    if isinstance(data, dict):
        data = [data]

    print(f'[*] enriching {len(data)} target(s)…', file=sys.stderr)
    results = enrich(data, args.token)

    print_report(results)

    if args.json_out:
        with open(args.json_out, 'w') as f:
            json.dump(results, f, indent=2)
        print(f'\n[+] enriched JSON → {args.json_out}', file=sys.stderr)


if __name__ == '__main__':
    main()
