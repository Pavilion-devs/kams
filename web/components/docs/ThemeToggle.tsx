"use client";

import { useEffect, useState } from "react";
import { Icon } from "@iconify/react";

const KEY = "kams-docs-theme";

/** Dark/light toggle scoped to the docs subtree (class on <html>, persisted). */
export default function ThemeToggle() {
  const [theme, setTheme] = useState<"dark" | "light">("light");

  // Sync from whatever the no-flash script (or a previous visit) already set.
  useEffect(() => {
    const stored =
      (typeof localStorage !== "undefined" &&
        (localStorage.getItem(KEY) as "dark" | "light" | null)) ||
      null;
    const current =
      stored ?? (document.documentElement.classList.contains("dark") ? "dark" : "light");
    setTheme(current);
    document.documentElement.classList.toggle("dark", current === "dark");
  }, []);

  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    try {
      localStorage.setItem(KEY, next);
    } catch {
      /* ignore */
    }
    document.documentElement.classList.toggle("dark", next === "dark");
  };

  return (
    <button
      onClick={toggle}
      aria-label="Toggle theme"
      className="grid h-9 w-9 place-items-center rounded-lg text-zinc-500 transition-colors hover:bg-zinc-100 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-white"
    >
      <Icon
        icon={theme === "dark" ? "solar:moon-linear" : "solar:sun-2-linear"}
        className="h-[18px] w-[18px]"
      />
    </button>
  );
}
