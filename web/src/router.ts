import { useEffect, useState } from "react";

const NAV_EVENT = "khandaq:nav";

/** Minimal in-app router (R1). TanStack Router adoption is a follow-up; this keeps the build lean. */
export function navigate(to: string): void {
  window.history.pushState({}, "", to);
  window.dispatchEvent(new Event(NAV_EVENT));
}

export function usePath(): string {
  const [path, setPath] = useState(() => window.location.pathname);
  useEffect(() => {
    const onChange = () => setPath(window.location.pathname);
    window.addEventListener("popstate", onChange);
    window.addEventListener(NAV_EVENT, onChange);
    return () => {
      window.removeEventListener("popstate", onChange);
      window.removeEventListener(NAV_EVENT, onChange);
    };
  }, []);
  return path;
}
