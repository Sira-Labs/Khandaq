import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { api } from "../api";
import { navigate } from "../router";

export function Engagements() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["engagements"],
    queryFn: api.listEngagements,
  });
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: () => api.createEngagement(name),
    onSuccess: (e) => {
      setName("");
      qc.invalidateQueries({ queryKey: ["engagements"] });
      navigate(`/eng/${e.id}`);
    },
  });

  return (
    <div>
      <h1 className="mb-4 text-2xl font-semibold">Engagements</h1>
      <form
        className="mb-6 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) create.mutate();
        }}
      >
        <input
          aria-label="new engagement name"
          className="flex-1 rounded border border-white/15 bg-black/30 px-3 py-2"
          placeholder="New engagement name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button
          className="rounded bg-[var(--ember)] px-4 py-2 font-medium text-black disabled:opacity-50"
          disabled={!name.trim() || create.isPending}
        >
          Create
        </button>
      </form>

      {isLoading && <p className="text-[var(--muted)]">Loading…</p>}
      {error && <p className="text-red-400">Could not load engagements. Sign in above.</p>}
      <ul className="divide-y divide-white/10">
        {data?.map((e) => (
          <li key={e.id}>
            <button
              className="flex w-full items-center justify-between py-3 text-left hover:text-[var(--ember)]"
              onClick={() => navigate(`/eng/${e.id}`)}
            >
              <span>{e.name}</span>
              <span className="text-xs uppercase text-[var(--muted)]">{e.state}</span>
            </button>
          </li>
        ))}
        {data?.length === 0 && <li className="py-3 text-[var(--muted)]">No engagements yet.</li>}
      </ul>
    </div>
  );
}
