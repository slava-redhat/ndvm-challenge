"""Golden-set retrieval eval: does the RAG return the RIGHT mitigation chunk?

Curated YAML options are needles in a large PDF haystack. Production option synthesis
searches doc_type=mitigation only (`--mode catalog`). Measure recall@k / MRR before
and after catalog or retrieval changes.

    # inside the orchestrator container (has DB + Ollama embeddings):
    python tests/eval_retrieval.py            # dense (current rag_search)
    python tests/eval_retrieval.py --mode hybrid   # dense + Postgres FTS, RRF-fused
    python tests/eval_retrieval.py --mode catalog  # mitigation allow-list only
    python tests/eval_retrieval.py --k 6 --mode both
"""
import argparse
import sys

from db import rag_search

# (query, platform, expected) — expected matches a hit's source_url OR text (case-insensitive).
# Mix of paraphrase (dense should handle) and bare identifiers (lexical/hybrid should win).
GOLD = [
    ("patch a kernel flaw without rebooting the server", "rhel", "solutions/2206511"),
    ("keep an exploit contained at the service level with mandatory access control", "rhel", "solutions/7032454"),
    ("remove network reachability to the vulnerable port", "rhel", "solutions/962473"),
    ("the optional module carrying the bug is not used, switch it off", "rhel", "disable the vulnerable module"),
    ("Red Hat signed data says our version is not affected, what do we record", "rhel", "csaf/v2/vex"),
    ("stop other pods from reaching the vulnerable workload", "openshift", "solutions/3660771"),
    ("prevent a bad container image from being admitted to the cluster", "openshift", "advanced-cluster-security"),
    ("reduce the privileges a pod is allowed to run with", "openshift", "solutions/5243301"),
    # bare identifiers — dense embeddings tend to bury these under prose:
    ("kpatch", "rhel", "solutions/2206511"),
    ("NetworkPolicy", "openshift", "solutions/3660771"),
    ("SELinux enforcing confinement", "rhel", "solutions/7032454"),
    ("VEX known_not_affected", "rhel", "csaf/v2/vex"),
    # catalog depth / unknown path: curated hit vs thin query that should miss catalog
    ("openssh MaxStartups sshd_config", "rhel", "solutions/54099"),
    ("EgressNetworkPolicy AdminNetworkPolicy restrict outbound", "openshift", "solutions/7092810"),
]


def _search(query, platform, k, mode):
    if mode in ("hybrid", "catalog"):
        from db import rag_search_hybrid
        kwargs = {"doc_types": ("mitigation",)} if mode == "catalog" else {}
        return rag_search_hybrid(query, platform, k, **kwargs)
    return rag_search(query, platform, k)


def _rank(hits, expected) -> int:
    """1-based rank of the first hit matching `expected`, or 0 if absent."""
    exp = expected.lower()
    for i, h in enumerate(hits, 1):
        if exp in (h.get("source_url") or "").lower() or exp in (h.get("text") or "").lower():
            return i
    return 0


def evaluate(mode: str, k: int, verbose: bool = True) -> dict:
    hit, rr = 0, 0.0
    for query, platform, expected in GOLD:
        hits = _search(query, platform, k, mode)
        rank = _rank(hits, expected)
        if rank:
            hit += 1
            rr += 1.0 / rank
        if verbose:
            mark = f"#{rank}" if rank else "MISS"
            print(f"  [{mark:>5}] {query[:52]:<52} -> {expected}")
    n = len(GOLD)
    res = {"mode": mode, "k": k, "recall": hit / n, "mrr": rr / n, "n": n}
    if verbose:
        print(f"  == {mode}: recall@{k}={res['recall']:.2f}  MRR={res['mrr']:.3f}  (n={n})")
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["dense", "hybrid", "catalog", "both"], default="dense")
    ap.add_argument("--k", type=int, default=6)
    args = ap.parse_args()
    modes = ["dense", "hybrid"] if args.mode == "both" else [args.mode]
    results = []
    for m in modes:
        print(f"\n=== {m} (k={args.k}) ===")
        results.append(evaluate(m, args.k))
    if len(results) == 2:
        d, h = results
        print(f"\nΔ hybrid vs dense: recall {h['recall']-d['recall']:+.2f}, "
              f"MRR {h['mrr']-d['mrr']:+.3f}")
    # ponytail self-check: _rank must find/miss correctly regardless of DB state.
    assert _rank([{"source_url": "a/solutions/2206511", "text": ""}], "solutions/2206511") == 1
    assert _rank([{"source_url": "x", "text": "y"}], "nope") == 0
    sys.exit(0)
