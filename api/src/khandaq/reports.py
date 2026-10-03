"""Engagement report builder (specs 011 and 013).

Assembles canonical findings into a management summary + technical report, pins the evidence-ledger
root and the entry count it covers (ADR-0007), and produces a MITRE ATLAS Navigator layer via the
Rust core. Offers JSON and a self-contained HTML rendering (finding text is untrusted, so it is
escaped). Every export is audited with the pin it issued, and a pin taken from an exported report
can be re-verified against the current chain.
"""

from __future__ import annotations

import datetime as dt
import html
import json
from collections import Counter

import khandaq_core as kc
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from . import ledger as ledger_svc
from .models import AuditLog, Engagement, Finding, User

EXPORT_ACTION = "report.exported"

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _canonical_findings(session: Session, engagement_id: str) -> list[Finding]:
    return list(
        session.scalars(
            select(Finding)
            .where(Finding.engagement_id == engagement_id, Finding.canonical.is_(True))
            .order_by(Finding.created_at.desc())
        ).all()
    )


def build_report(session: Session, engagement: Engagement) -> dict:
    findings = _canonical_findings(session, engagement.id)
    chain = ledger_svc.chain_status(session, engagement.id)  # root + verify from one read
    by_severity: Counter[str] = Counter(f.severity for f in findings)
    by_framework: Counter[str] = Counter()
    finding_views = []
    for f in findings:
        xk = (f.body or {}).get("x-khandaq", {})
        mappings = xk.get("mappings", [])
        for m in mappings:
            by_framework[f"{m['framework']}:{m['id']}"] += 1
        finding_views.append(
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "phase": xk.get("phase"),
                "mappings": mappings,
                "evidence": xk.get("evidence", []),
                "also_found_by": xk.get("also_found_by", []),
            }
        )

    return {
        "engagement": {
            "id": engagement.id,
            "name": engagement.name,
            "client": engagement.client,
            "state": engagement.state,
            "authorisation_ref": engagement.authorisation_ref,
        },
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        # Root and count come from the same read, so the pin never mixes two chain states.
        "evidence": {"root": chain["root"], "count": chain["count"], "verify": chain["verify"]},
        "summary": {
            "total": len(findings),
            "by_severity": {s: by_severity.get(s, 0) for s in _SEV_ORDER if by_severity.get(s)},
            "by_framework": dict(sorted(by_framework.items())),
        },
        "findings": finding_views,
        # The table versions the framework ids refer to (spec 020).
        "mapping_tables": _mapping_tables(),
    }


def _mapping_tables() -> dict:
    table = json.loads(kc.mapping_table())
    return {"versions": table["versions"], "sources": table["sources"]}


def record_export(session: Session, report: dict, *, fmt: str, actor: User) -> None:
    """Audit an export with the pin it issued (doc 04 lists report export as audited). Caller
    commits before responding, so every report this instance hands out is on record."""
    ev = report["evidence"]
    audit.record(
        session,
        action=EXPORT_ACTION,
        actor=actor,
        engagement_id=report["engagement"]["id"],
        detail={"format": fmt, "root": ev["root"], "count": ev["count"]},
    )


def _was_issued(session: Session, engagement_id: str, root: str | None, count: int) -> bool:
    match = {"root": root, "count": count}
    found = session.scalar(
        select(AuditLog.id)
        .where(
            AuditLog.engagement_id == engagement_id,
            AuditLog.action == EXPORT_ACTION,
            AuditLog.detail.contains(match),
        )
        .limit(1)
    )
    return found is not None


def verify_pin(session: Session, engagement: Engagement, root: str | None, count: int) -> dict:
    """Re-verify a report's pin against the current chain (spec 013). Read-only.

    ``issued`` is information, not a condition of ``ok``: a well-formed pin with no export on
    record (one read from ``GET /ledger``) still verifies, and a client reads ``ok and not issued``
    as "the evidence is intact, but this instance has no record of issuing this pin". A report from
    before spec 013 has no ``count`` and is refused by ``ReportPin`` (422)."""
    state = ledger_svc.verify_pin(session, engagement.id, root, count)
    ok = bool(state["verify"].get("ok"))
    return {
        "ok": ok,
        "pinned": {"root": root, "count": count},
        "current": state["current"],
        "appended_since": state["current"]["count"] - count if ok else None,
        "issued": _was_issued(session, engagement.id, root, count),
        "verify": state["verify"],
    }


def navigator_layer(session: Session, engagement: Engagement) -> dict:
    bodies = [f.body for f in _canonical_findings(session, engagement.id)]
    return json.loads(kc.navigator(json.dumps(bodies)))


def render_html(report: dict) -> str:
    e = report["engagement"]
    ev = report["evidence"]
    verify = "intact ✓" if ev["verify"].get("ok") else f"BROKEN at #{ev['verify'].get('broken_at')}"
    sev_rows = "".join(
        f"<tr><td>{html.escape(s)}</td><td>{n}</td></tr>"
        for s, n in report["summary"]["by_severity"].items()
    )
    fw_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{n}</td></tr>"
        for k, n in report["summary"]["by_framework"].items()
    )
    tables = " · ".join(
        f"{html.escape(fw)} {html.escape(v)}"
        for fw, v in report.get("mapping_tables", {}).get("versions", {}).items()
    )
    find_rows = "".join(
        "<tr>"
        f"<td>{html.escape(f['severity'])}</td>"
        f"<td>{html.escape(f['title'] or f['rule_id'])}</td>"
        f"<td>{html.escape(', '.join(m['id'] for m in f['mappings']))}</td>"
        f"<td>{len(f['evidence'])}</td>"
        "</tr>"
        for f in report["findings"]
    )
    name = html.escape(e["name"])
    state = html.escape(e["state"])
    auth = html.escape(e["authorisation_ref"] or "—")
    gen = html.escape(report["generated_at"])
    root = html.escape(ev["root"] or "—")
    count = int(ev["count"])
    css = (
        "body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0}"
        "th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}"
        "h1,h2{font-family:Georgia,serif}"
    )
    none2 = "<tr><td colspan=2>none</td></tr>"
    none4 = "<tr><td colspan=4>none</td></tr>"
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        f"<title>Khandaq report — {name}</title><style>{css}</style></head><body>",
        "<h1>Khandaq engagement report</h1>",
        f"<p><strong>{name}</strong> · state: {state} · authorisation: {auth}</p>",
        f"<p>Generated {gen}. Evidence ledger root <code>{root}</code> over {count} "
        f"entr{'y' if count == 1 else 'ies'} — {verify}.</p>",
        "<h2>Summary by severity</h2><table><tr><th>severity</th><th>count</th></tr>",
        (sev_rows or none2) + "</table>",
        "<h2>Summary by framework</h2><table><tr><th>framework id</th><th>count</th></tr>",
        (fw_rows or none2) + "</table>",
        f"<p>Framework tables: {tables or '—'}.</p>",
        "<h2>Findings</h2><table>",
        "<tr><th>severity</th><th>finding</th><th>frameworks</th><th>evidence</th></tr>",
        (find_rows or none4) + "</table>",
        "<p><em>For authorised security testing only.</em></p></body></html>",
    ]
    return "\n".join(parts)
