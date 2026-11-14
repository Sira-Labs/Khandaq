import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";

import { api, type Target } from "../api";

const input = "rounded border border-white/15 bg-black/30 px-2 py-1 text-sm";
const button = "rounded border border-white/20 px-3 py-1 text-sm disabled:opacity-40";

function updated(at: string | null | undefined): string {
  return at ? `, updated ${new Date(at).toISOString().slice(0, 10)}` : "";
}

/**
 * A target's API-key status and, for the engagement owner, the controls to set, replace or remove
 * it (spec 028). The key is write-only: it lives in this component's password field until it is
 * sent, is never passed through the query cache (the mutation reads it from a ref, so it is not
 * kept as mutation variables), is never stored, and is never shown again.
 */
export function TargetCredential({
  engagementId,
  target,
  canEdit,
}: {
  engagementId: string;
  target: Target;
  canEdit: boolean;
}) {
  const qc = useQueryClient();
  const [value, setValue] = useState("");
  const pending = useRef("");
  const refresh = () => qc.invalidateQueries({ queryKey: ["targets", engagementId] });
  const forget = () => {
    pending.current = "";
    setValue("");
  };

  const save = useMutation({
    gcTime: 0,
    mutationFn: () => api.setCredential(engagementId, target.id, pending.current),
    onSettled: forget, // whatever the API answered, the key does not stay in the page
    onSuccess: refresh,
  });
  const remove = useMutation({
    gcTime: 0,
    mutationFn: () => api.clearCredential(engagementId, target.id),
    onSettled: forget,
    onSuccess: refresh,
  });

  const has = !!target.has_credential;
  const status = has ? `key set${updated(target.credential_updated_at)}` : "no key";
  const error = save.error ?? remove.error;

  return (
    <span className="ml-2 inline-flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
      <span data-testid={`credential-status-${target.id}`}>{status}</span>
      {canEdit && (
        <form
          className="inline-flex flex-wrap items-center gap-2"
          autoComplete="off"
          onSubmit={(e) => {
            e.preventDefault();
            if (!value) return;
            pending.current = value;
            setValue("");
            save.mutate();
          }}
        >
          <input
            aria-label={`API key for ${target.id}`}
            className={`${input} w-56`}
            type="password"
            autoComplete="new-password"
            spellCheck={false}
            placeholder={has ? "new key" : "API key"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
          <button className={button} disabled={!value || save.isPending}>
            {has ? "Replace key" : "Set key"}
          </button>
          {has && (
            <button
              type="button"
              className={button}
              disabled={remove.isPending}
              onClick={() => remove.mutate()}
            >
              Remove key
            </button>
          )}
        </form>
      )}
      {error && (
        <span className="text-red-400" role="alert">
          Could not change the key: {error.message}
        </span>
      )}
    </span>
  );
}
