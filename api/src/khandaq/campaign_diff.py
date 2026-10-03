"""The diff a successful campaign run records against the campaign's earlier runs (spec 016 §4).

A run's sightings are the fingerprints of its findings rows (canonical or linked duplicates), so a
finding counts for every run that saw it, not only the first. Against the campaign's earlier
successful runs:

- ``new``       — never seen by an earlier run;
- ``regressed`` — seen before, absent from the previous run, back now;
- ``resolved``  — in the previous run, gone now;
- unchanged     — in both (counted only).

The first successful run is the baseline. A diff with new or regressed findings is ``worsened``.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import alerts, audit
from .models import CampaignDiff, Finding, Run


def _sightings(session: Session, run_ids: list[str]) -> dict[str, dict[str, Finding]]:
    """Per run: fingerprint → one findings row of that run."""
    out: dict[str, dict[str, Finding]] = {rid: {} for rid in run_ids}
    if not run_ids:
        return out
    for row in session.scalars(select(Finding).where(Finding.run_id.in_(run_ids))):
        out[row.run_id].setdefault(row.fingerprint, row)
    return out


def _entry(row: Finding, canonical: dict[str, str]) -> dict:
    """What a diff lists for a fingerprint. The title is untrusted text, stored as data."""
    return {
        "fingerprint": row.fingerprint,
        "finding_id": canonical.get(row.fingerprint, row.id),
        "rule_id": row.rule_id,
        "severity": row.severity,
        "title": row.title,
    }


def record_diff(session: Session, run: Run) -> CampaignDiff:
    """Store and audit the diff of a campaign run that has just succeeded. Caller commits."""
    if run.campaign_id is None:
        raise ValueError(f"run {run.id} belongs to no campaign")
    session.flush()  # this run's findings rows must be visible to the query below
    earlier = list(
        session.scalars(
            select(Run.id)
            .where(
                Run.campaign_id == run.campaign_id,
                Run.state == "succeeded",
                Run.id != run.id,
                Run.created_at <= run.created_at,
            )
            .order_by(Run.created_at, Run.id)
        )
    )
    seen = _sightings(session, [*earlier, run.id])
    current = seen.pop(run.id)
    rows = session.execute(
        select(Finding.fingerprint, Finding.id).where(
            Finding.engagement_id == run.engagement_id,
            Finding.canonical.is_(True),
            Finding.fingerprint.in_(list(current) + [fp for s in seen.values() for fp in s]),
        )
    )
    canonical: dict[str, str] = {fingerprint: finding_id for fingerprint, finding_id in rows}

    if not earlier:
        diff = CampaignDiff(
            campaign_id=run.campaign_id,
            run_id=run.id,
            previous_run_id=None,
            baseline=True,
            new=[],
            regressed=[],
            resolved=[],
            unchanged_count=0,
            findings_count=len(current),
            worsened=False,
        )
    else:
        previous_id = earlier[-1]
        previous = seen[previous_id]
        ever = {fp for sightings in seen.values() for fp in sightings}
        new = [fp for fp in current if fp not in ever]
        regressed = [fp for fp in current if fp in ever and fp not in previous]
        resolved = [fp for fp in previous if fp not in current]
        diff = CampaignDiff(
            campaign_id=run.campaign_id,
            run_id=run.id,
            previous_run_id=previous_id,
            baseline=False,
            new=[_entry(current[fp], canonical) for fp in sorted(new)],
            regressed=[_entry(current[fp], canonical) for fp in sorted(regressed)],
            resolved=[_entry(previous[fp], canonical) for fp in sorted(resolved)],
            unchanged_count=sum(1 for fp in current if fp in previous),
            findings_count=len(current),
            worsened=bool(new or regressed),
        )
    session.add(diff)
    audit.record(
        session,
        action="campaign.diff",
        engagement_id=run.engagement_id,
        detail={
            "campaign_id": run.campaign_id,
            "run_id": run.id,
            "baseline": diff.baseline,
            "new": len(diff.new),
            "regressed": len(diff.regressed),
            "resolved": len(diff.resolved),
            "worsened": diff.worsened,
        },
    )
    alerts.queue_for_diff(session, diff, run)  # spec 017: same transaction as the diff
    return diff
