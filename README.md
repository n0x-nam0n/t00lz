# attack_graph.py takes a domain, resolves its IPs, queries Shodan for open ports/services, looks up CVEs for those services via NVD, searches GitHub for exposed secrets, then scores each IP and renders a priority-ranked attack graph with MSF module suggestions. Feed it a domain → get "attack this IP first, here's the CVE, here's the module.

# pipe attack_graph output directly
python3 ~/scripts/recon/attack_graph.py doge.gov --out /tmp/doge.json
python3 ~/scripts/recon/github_enrich.py /tmp/doge.json \
    --token "yourgittoken" \
    --json-out /tmp/doge_enriched.json

# or pipe
python3 ~/scripts/recon/attack_graph.py doge.gov | \
    python3 ~/scripts/recon/github_enrich.py - --token ghp_...

What it does per hit:
- Converts github.com/user/repo/blob/… → raw.githubusercontent.com and fetches up to 200KB
- Runs 22 regex patterns against every line: AWS keys, GitHub PATs, Stripe/SendGrid/Slack/OpenAI tokens, passwords, DB connection strings, PEM blocks, OAuth secrets
- Color-coded terminal report: red = secrets found, green = clean; prints kind, line number, extracted value, and surrounding context
- Optional --json-out for the enriched JSON
