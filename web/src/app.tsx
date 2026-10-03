import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ApiError, api, getDevUser, loginUrl, setDevUser, type Me } from "./api";
import { Campaign } from "./pages/Campaign";
import { Engagement } from "./pages/Engagement";
import { Engagements } from "./pages/Engagements";
import { Findings } from "./pages/Findings";
import { navigate, usePath } from "./router";

/** Development only: the API runs its dev login stub (never in production). */
function DevIdentity() {
  const qc = useQueryClient();
  const [email, setEmail] = useState(getDevUser());
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="text-[var(--muted)]">dev identity</span>
      <input
        aria-label="dev user email"
        className="rounded border border-white/15 bg-black/30 px-2 py-1"
        value={email}
        placeholder="you@example.org"
        onChange={(e) => setEmail(e.target.value)}
        onBlur={() => {
          setDevUser(email);
          qc.invalidateQueries();
        }}
      />
    </div>
  );
}

function SignedIn({ me }: { me: Me }) {
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  if (me.auth === "dev") return <DevIdentity />;
  return (
    <div className="flex items-center gap-3 text-sm">
      <span className="text-[var(--muted)]">{me.display_name || me.email}</span>
      {me.auth === "session" && (
        <button
          className="text-[var(--ember)] disabled:opacity-50"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setFailed(null);
            try {
              await api.logout();
            } catch (err) {
              // The server session is still live: stay here and say so, rather than pretend.
              setFailed(err instanceof Error ? err.message : String(err));
              setBusy(false);
              return;
            }
            window.location.assign("/");
          }}
        >
          Sign out
        </button>
      )}
      {failed && (
        <span role="alert" className="text-red-400">
          Sign-out failed ({failed}); try again.
        </span>
      )}
    </div>
  );
}

/** Not signed in, or signed in without access. Never redirects on its own: with an IdP session
 * for a refused account, an automatic redirect would bounce between the IdP and this page. */
function SignIn({ denied }: { denied: boolean }) {
  const next = window.location.pathname + window.location.search.replace(/[?&]signin=denied/, "");
  return (
    <div className="mx-auto mt-16 max-w-md space-y-4 text-center">
      <h1 className="text-2xl font-semibold">Sign in to Khandaq</h1>
      {denied ? (
        <p role="alert" className="text-red-400">
          That account has no access to this Khandaq. Ask the owner to add your email address to the
          allow-list, or sign in with another account.
        </p>
      ) : (
        <p className="text-[var(--muted)]">For authorised AI red-team engagements only.</p>
      )}
      <a
        className="inline-block rounded bg-[var(--ember)] px-5 py-2 font-medium text-black"
        href={loginUrl(denied ? "/" : next || "/")}
      >
        {denied ? "Sign in with another account" : "Sign in"}
      </a>
    </div>
  );
}

export function App() {
  const path = usePath();
  const me = useQuery({
    queryKey: ["me"],
    queryFn: api.me,
    // A blip (network, 5xx) should not replace the console with an error; "not signed in" (401) and
    // "no access" (403) are answers, not failures, so they are never retried.
    retry: (failures, err) =>
      !(err instanceof ApiError && (err.status === 401 || err.status === 403)) && failures < 2,
  });
  const deniedLanding = new URLSearchParams(window.location.search).get("signin") === "denied";

  let body: React.ReactNode;
  if (me.isLoading) {
    body = <p className="text-[var(--muted)]">Loading…</p>;
  } else if (me.error) {
    const status = me.error instanceof ApiError ? me.error.status : 0;
    if (status === 401 || status === 403) {
      body = <SignIn denied={deniedLanding || status === 403} />;
    } else {
      body = (
        <p role="alert" className="text-red-400">
          Khandaq is not reachable right now ({me.error.message}).
        </p>
      );
    }
  } else if (deniedLanding) {
    // The callback refused the account; a still-valid earlier session must not hide that.
    body = <SignIn denied />;
  } else {
    const findings = path.match(/^\/eng\/([^/]+)\/findings$/);
    const campaign = path.match(/^\/eng\/([^/]+)\/campaigns\/([^/]+)$/);
    const detail = path.match(/^\/eng\/([^/]+)$/);
    if (findings) body = <Findings engagementId={findings[1]} />;
    else if (campaign) body = <Campaign engagementId={campaign[1]} campaignId={campaign[2]} />;
    else if (detail) body = <Engagement engagementId={detail[1]} />;
    else body = <Engagements />;
  }

  return (
    <div className="min-h-screen">
      <header className="flex items-center justify-between border-b border-white/10 px-6 py-3">
        <button className="text-xl font-semibold text-[var(--fg)]" onClick={() => navigate("/")}>
          Khandaq
        </button>
        {me.data && !me.error && <SignedIn me={me.data} />}
      </header>
      <main className="mx-auto max-w-5xl px-6 py-8">{body}</main>
    </div>
  );
}
