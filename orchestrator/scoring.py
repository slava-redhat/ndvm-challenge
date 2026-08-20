"""Deterministic option scoring — so the ranking is reproducible and auditable.

The LLM Strategist used to *decide* the order by eyeballing three numbers, which meant
two runs could reorder options and a customer couldn't see *why* rank 1 beat rank 2. Here
the order is a pure function of the option's own attributes; the LLM keeps the narrative
(the `explanation`) and can still break genuine ties in prose. Higher score = better fit.

Weights: disruption dominates — non-disruptive is the whole point of NDVM — then more
effectiveness helps and more effort hurts. When the customer explicitly can't take
downtime, disruption weighs even heavier; when the CVE is actively exploited / high-EPSS,
effectiveness weighs more (cut exposure fast, tolerate a bit more effort).
"""
import re

# none = best (0 penalty) ... high = worst; disruption_score = 3 - rank (higher better).
DISRUPTION_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}

# Require an explicit uptime constraint — bare "maintenance window" means one EXISTS.
_NO_DOWNTIME = re.compile(
    r"no[\s-]*(reboot|downtime|outage|restart|maintenance\s+window)|"
    r"can(?:not|'t)\s+(reboot|restart)|"
    r"without\s+(a\s+)?(reboot|downtime|outage)|"
    r"until\s+(?:the\s+)?(?:next\s+)?maintenance", re.I)


def no_downtime(constraint: str) -> bool:
    """True when the stated constraint rules out reboots/outages (weights disruption up)."""
    return bool(_NO_DOWNTIME.search(constraint or ""))


def score_option(disruption: str, effectiveness: int, effort: int,
                 strict_uptime: bool = False, urgent: bool = False) -> float:
    """Reproducible desirability of one mitigation for this case. Higher = recommend first."""
    d_score = 3 - DISRUPTION_RANK.get((disruption or "").lower(), 3)   # 0..3, higher better
    w_d = 3.0 if strict_uptime else 2.0
    eff = int(effectiveness or 0)
    score = w_d * d_score + eff - int(effort or 0)
    if urgent:                       # actively exploited: value fast exposure-cut more
        score += 0.5 * eff
    return round(score, 1)


def rank_options(options: list, constraint: str = "", urgent: bool = False) -> list:
    """Sort options in place by score (desc); annotate each with its `score`. Stable, so
    the LLM's original order breaks exact numeric ties. Returns the same list."""
    strict = no_downtime(constraint)
    for o in options:
        o.score = score_option(o.disruption, o.effectiveness, o.effort, strict, urgent)
    options.sort(key=lambda o: o.score, reverse=True)
    return options


if __name__ == "__main__":
    from types import SimpleNamespace as O

    # A non-disruptive, effective, cheap option beats a disruptive one.
    assert score_option("none", 4, 1) > score_option("high", 4, 1)
    # Effort penalises; effectiveness rewards.
    assert score_option("low", 4, 1) > score_option("low", 4, 4)
    assert score_option("low", 4, 2) > score_option("low", 2, 2)
    # "no reboot" tips the balance toward the lower-disruption option: a more-effective,
    # cheaper medium-disruption option wins normally, but a costlier no-disruption one
    # overtakes it once uptime is strict.
    a = ("none", 2, 4); b = ("medium", 4, 1)
    assert score_option(*a) < score_option(*b)                     # normally b wins
    assert score_option(*a, strict_uptime=True) > score_option(*b, strict_uptime=True)  # flips
    # rank_options sorts + annotates, recommended = first.
    opts = [O(title="reboot-patch", disruption="high", effectiveness=4, effort=2, score=None),
            O(title="livepatch", disruption="none", effectiveness=3, effort=1, score=None)]
    rank_options(opts, constraint="can't reboot until quarter-end")
    assert opts[0].title == "livepatch" and opts[0].score is not None
    # Positive maintenance window is NOT a no-downtime constraint.
    assert no_downtime("open maintenance window available") is False
    assert no_downtime("no maintenance window until quarter-end") is True
    assert no_downtime("cannot reboot this host") is True
    print("ok")
