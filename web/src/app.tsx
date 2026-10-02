import { useState } from "react";

import { getDevUser, setDevUser } from "./api";
import { Engagement } from "./pages/Engagement";
import { Engagements } from "./pages/Engagements";
import { Findings } from "./pages/Findings";
import { navigate, usePath } from "./router";

function DevBar() {
  const [email, setEmail] = useState(getDevUser());
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="text-[var(--muted)]">signed in as</span>
      <input
        aria-label="dev user email"
        className="rounded border border-white/15 bg-black/30 px-2 py-1"
        value={email}
        placeholder="you@example.org"
        onChange={(e) => setEmail(e.target.value)}
        onBlur={() => setDevUser(email)}
      />
    </div>
  );
}

export function App() {
  const path = usePath();
  let page = <Engagements />;
  const findings = path.match(/^\/eng\/([^/]+)\/findings$/);
  const detail = path.match(/^\/eng\/([^/]+)$/);
  if (findings) page = <Findings engagementId={findings[1]} />;
  else if (detail) page = <Engagement engagementId={detail[1]} />;

  return (
    <div className="min-h-screen">
      <header className="flex items-center justify-between border-b border-white/10 px-6 py-3">
        <button
          className="text-xl font-semibold text-[var(--fg)]"
          onClick={() => navigate("/")}
        >
          Khandaq
        </button>
        <DevBar />
      </header>
      <main className="mx-auto max-w-5xl px-6 py-8">{page}</main>
    </div>
  );
}
