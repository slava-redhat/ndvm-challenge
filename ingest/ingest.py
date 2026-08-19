"""One-shot ingest: mitigation catalog + hardening PDFs + seed CVEs -> pgvector.

Idempotent enough for a demo: clears doc_chunk/mitigation and reloads.
"""
import glob
import os

import psycopg
import requests
import yaml
from pypdf import PdfReader

from embeddings import embed, ensure_model

DATA = os.environ.get("DATA_DIR", "/app/data")
SECDATA = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
SEED_CVES = os.environ.get(
    "INGEST_CVES",
    "CVE-2024-3094,CVE-2023-3390,CVE-2021-44228,CVE-2022-0847",
).split(",")


def conn():
    return psycopg.connect(
        host=os.environ.get("PGHOST", "db"), port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ["POSTGRES_DB"], user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
    )


def vec(v: list[float]) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"


def add_chunk(cur, text, source_url, platform, doc_type):
    cur.execute(
        "INSERT INTO doc_chunk (text, source_url, metadata, embedding) "
        "VALUES (%s, %s, %s::jsonb, %s::vector)",
        (text, source_url,
         f'{{"platform":"{platform}","doc_type":"{doc_type}"}}',
         vec(embed(text))),
    )


def load_mitigations(cur):
    for path in glob.glob(f"{DATA}/mitigations/*.yaml"):
        doc = yaml.safe_load(open(path))
        platform = doc["platform"]
        for m in doc["mitigations"]:
            cur.execute(
                "INSERT INTO mitigation (platform, title, action_type, description, "
                "disruption, effectiveness, effort, applies_when, source_url) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (platform, m["title"], m["action_type"], m["description"],
                 m["disruption"], m["effectiveness"], m["effort"],
                 m.get("applies_when", ""), m.get("source_url", "")),
            )
            text = f"{m['title']} ({m['action_type']}, disruption={m['disruption']}). " \
                   f"{m['description']} Applies when: {m.get('applies_when','')}"
            add_chunk(cur, text, m.get("source_url", ""), platform, "mitigation")
    print("mitigations loaded")


def chunk(text: str, size: int = 800, overlap: int = 100):
    text = " ".join(text.split())
    i = 0
    while i < len(text):
        yield text[i:i + size]
        i += size - overlap


def load_pdfs(cur):
    for path in glob.glob(f"{DATA}/pdfs/*.pdf"):
        try:
            reader = PdfReader(path)
        except Exception as e:
            print(f"skip {path}: {e}"); continue
        full = "\n".join((p.extract_text() or "") for p in reader.pages)
        for c in chunk(full):
            if c.strip():
                add_chunk(cur, c, os.path.basename(path), "any", "pdf")
        print(f"pdf loaded: {os.path.basename(path)}")


def load_cves(cur):
    for cve in [c.strip() for c in SEED_CVES if c.strip()]:
        try:
            r = requests.get(SECDATA.format(cve=cve),
                             params={"isCompressed": "false"}, timeout=30)
            if r.status_code != 200:
                print(f"skip {cve}: HTTP {r.status_code}"); continue
            data = r.json()
        except Exception as e:
            print(f"skip {cve}: {e}"); continue
        sev = data.get("threat_severity", "unknown")
        try:
            cvss = float(data.get("cvss3", {}).get("cvss3_base_score"))
        except (TypeError, ValueError):
            cvss = None
        summary = (data.get("bugzilla", {}) or {}).get("description") or \
                  " ".join(data.get("details", []) or [])[:500]
        url = f"https://access.redhat.com/security/cve/{cve}"
        cur.execute(
            "INSERT INTO cve (cve_id, threat_severity, cvss3, summary, source_url) "
            "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (cve_id) DO UPDATE SET "
            "threat_severity=EXCLUDED.threat_severity, cvss3=EXCLUDED.cvss3",
            (cve, sev, cvss, summary, url),
        )
        for st in data.get("package_state", []) or []:
            cur.execute(
                "INSERT INTO cve_product_state (cve_id, product_name, fix_state) "
                "VALUES (%s,%s,%s)",
                (cve, st.get("product_name"), st.get("fix_state")),
            )
        for rel in data.get("affected_release", []) or []:
            cur.execute(
                "INSERT INTO cve_product_state (cve_id, product_name, fix_state, rhsa, fixed_nvra) "
                "VALUES (%s,%s,'Fixed',%s,%s)",
                (cve, rel.get("product_name"), rel.get("advisory"), rel.get("package")),
            )
        add_chunk(cur, f"{cve} ({sev}). {summary}", url, "any", "cve")
        print(f"cve loaded: {cve} ({sev})")


def main():
    ensure_model()
    with conn() as c, c.cursor() as cur:
        cur.execute("TRUNCATE doc_chunk, mitigation, cve_product_state, cve RESTART IDENTITY CASCADE")
        load_mitigations(cur)
        load_pdfs(cur)
        load_cves(cur)
        c.commit()
    print("ingest complete")


if __name__ == "__main__":
    main()
