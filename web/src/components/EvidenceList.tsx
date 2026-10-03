import { useState } from "react";

import { api, ApiError, saveDownload } from "../api";

function message(err: unknown): { text: string; integrity: boolean } {
  if (err instanceof ApiError) {
    if (err.status === 403)
      return { text: "Your role cannot download raw evidence (owner, operator or analyst only).", integrity: false };
    if (err.status === 404) return { text: "No stored content for this evidence.", integrity: false };
    if (err.status === 409)
      return { text: "Integrity check failed: the stored bytes do not match the sealed hash.", integrity: true };
    return { text: err.message, integrity: false };
  }
  return { text: err instanceof Error ? err.message : String(err), integrity: false };
}

/** A finding's sealed evidence, each downloadable as a file (spec 015 §3; never rendered). */
export function EvidenceList({ engagementId, evidenceIds }: { engagementId: string; evidenceIds: string[] }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, { text: string; integrity: boolean }>>({});

  async function fetchOne(id: string) {
    setBusy(id);
    setErrors(({ [id]: _, ...rest }) => rest);
    try {
      saveDownload(await api.downloadEvidence(engagementId, id));
    } catch (err) {
      setErrors((prev) => ({ ...prev, [id]: message(err) }));
    } finally {
      setBusy(null);
    }
  }

  if (evidenceIds.length === 0) return <span className="text-[var(--muted)]">none</span>;
  return (
    <ul className="space-y-1">
      {evidenceIds.map((id) => (
        <li key={id}>
          <div className="flex items-center gap-2">
            <code className="text-xs">{id}</code>
            <button
              className="text-xs text-[var(--ember)] disabled:opacity-40"
              disabled={busy === id}
              onClick={() => void fetchOne(id)}
            >
              Download
            </button>
          </div>
          {errors[id] && (
            <p role="alert" className={`text-xs ${errors[id].integrity ? "text-red-400 font-semibold" : "text-red-300"}`}>
              {errors[id].text}
            </p>
          )}
        </li>
      ))}
    </ul>
  );
}
