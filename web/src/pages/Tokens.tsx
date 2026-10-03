import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { api } from "../api";
import { formatTime } from "../components/RunsPanel";
import { navigate } from "../router";

/** Your API tokens (spec 019): for automation such as `deploy/smoke.py`. A new token is shown
 * once; the server stores only its hash. Creating and revoking are audited by the API. */
export function Tokens() {
  const qc = useQueryClient();
  const tokens = useQuery({ queryKey: ["tokens"], queryFn: api.listTokens });
  const [name, setName] = useState("");
  const [created, setCreated] = useState<{ name: string; token: string } | null>(null);

  const create = useMutation({
    mutationFn: () => api.createToken(name.trim()),
    onSuccess: (data) => {
      setCreated({ name: data.name, token: data.token });
      setName("");
      qc.invalidateQueries({ queryKey: ["tokens"] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tokens"] }),
  });

  return (
    <div className="space-y-6">
      <button className="text-sm text-[var(--muted)]" onClick={() => navigate("/")}>
        ← engagements
      </button>
      <h1 className="text-2xl font-semibold">API tokens</h1>
      <p className="text-sm text-[var(--muted)]">
        A token acts as you, with your roles, for scripts and CI. Keep it secret; revoke it when it
        is no longer needed.
      </p>

      <form
        className="flex flex-wrap items-center gap-2 text-sm"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate();
        }}
      >
        <input
          aria-label="token name"
          className="rounded border border-white/15 bg-black/30 px-2 py-1"
          placeholder="what is it for?"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button
          type="submit"
          className="rounded bg-[var(--ember)] px-3 py-1 font-medium text-black disabled:opacity-40"
          disabled={!name.trim() || create.isPending}
        >
          Create token
        </button>
      </form>
      {create.error && (
        <p className="text-sm text-red-400" role="alert">
          Could not create the token: {create.error.message}
        </p>
      )}
      {created && (
        <div className="rounded border border-amber-400/40 bg-amber-400/5 p-3 text-sm" role="status">
          <p className="font-semibold">Token “{created.name}” — copy it now; it will not be shown again.</p>
          <code className="mt-1 block break-all select-all" data-testid="new-token">
            {created.token}
          </code>
        </div>
      )}

      <section className="rounded border border-white/10 p-4">
        {tokens.error && (
          <p className="text-sm text-red-400" role="alert">
            Could not load tokens: {tokens.error.message}
          </p>
        )}
        <ul className="space-y-1 text-sm">
          {tokens.data?.map((t) => (
            <li key={t.id} className="flex items-center gap-2" data-testid="token-row">
              <span className="flex-1">{t.name}</span>
              <span className="text-xs text-[var(--muted)]">
                created {formatTime(t.created_at ?? undefined)}
                {t.last_used_at ? ` · last used ${formatTime(t.last_used_at)}` : " · never used"}
              </span>
              {t.revoked_at ? (
                <span className="text-xs text-[var(--muted)]">revoked</span>
              ) : (
                <button
                  className="text-xs text-red-300 disabled:opacity-40"
                  disabled={revoke.isPending}
                  onClick={() => revoke.mutate(t.id)}
                >
                  Revoke
                </button>
              )}
            </li>
          ))}
          {tokens.data?.length === 0 && <li className="text-[var(--muted)]">No tokens.</li>}
        </ul>
        {revoke.error && (
          <p className="mt-2 text-sm text-red-400" role="alert">
            Could not revoke the token: {revoke.error.message}
          </p>
        )}
      </section>
    </div>
  );
}
