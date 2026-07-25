"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Icon } from "@iconify/react";
import { flatDocs } from "@/lib/docs-nav";

/**
 * ⌘K palette over the same `flatDocs` array the sidebar and prev/next use, so
 * a page can never be reachable by one and invisible to the others.
 */
export default function SearchPalette() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return flatDocs;
    return flatDocs.filter((d) =>
      `${d.title} ${d.summary} ${d.group}`.toLowerCase().includes(q),
    );
  }, [query]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
      if (e.key === "Escape") setOpen(false);
    };
    const onOpen = () => setOpen(true);
    window.addEventListener("keydown", onKey);
    window.addEventListener("kams:open-search", onOpen);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("kams:open-search", onOpen);
    };
  }, []);

  useEffect(() => {
    if (open) {
      setQuery("");
      setCursor(0);
      // Focus after paint, or the input is not in the DOM yet.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => setCursor(0), [query]);

  if (!open) return null;

  const go = (slug: string) => {
    setOpen(false);
    router.push(slug);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => Math.min(c + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => Math.max(c - 1, 0));
    } else if (e.key === "Enter" && results[cursor]) {
      e.preventDefault();
      go(results[cursor].slug);
    }
  };

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center bg-zinc-900/40 px-4 pt-[12vh] backdrop-blur-sm dark:bg-black/60"
      onClick={() => setOpen(false)}
    >
      <div
        className="w-full max-w-xl overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-2xl dark:border-zinc-800 dark:bg-[#111114]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-zinc-200 px-4 dark:border-zinc-800">
          <Icon icon="solar:magnifer-linear" className="h-[18px] w-[18px] text-zinc-400" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Search the docs…"
            className="h-14 flex-1 bg-transparent text-[15px] text-zinc-900 outline-none placeholder:text-zinc-400 dark:text-white"
          />
          <kbd className="rounded border border-zinc-200 px-1.5 py-0.5 text-[10px] text-zinc-400 dark:border-zinc-700">
            ESC
          </kbd>
        </div>

        <ul className="max-h-[52vh] overflow-y-auto p-2">
          {results.length === 0 && (
            <li className="px-3 py-8 text-center text-[14px] text-zinc-400">
              No pages match “{query}”.
            </li>
          )}
          {results.map((d, i) => (
            <li key={d.slug}>
              <button
                onMouseEnter={() => setCursor(i)}
                onClick={() => go(d.slug)}
                className={`flex w-full flex-col items-start rounded-lg px-3 py-2.5 text-left transition-colors ${
                  i === cursor
                    ? "bg-blue-500/10"
                    : "hover:bg-zinc-100 dark:hover:bg-zinc-800/60"
                }`}
              >
                <span className="flex items-center gap-2">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
                    {d.group}
                  </span>
                </span>
                <span
                  className={`text-[14px] font-medium ${
                    i === cursor
                      ? "text-blue-600 dark:text-blue-400"
                      : "text-zinc-900 dark:text-white"
                  }`}
                >
                  {d.title}
                </span>
                <span className="mt-0.5 line-clamp-1 text-[12.5px] text-zinc-500 dark:text-zinc-400">
                  {d.summary}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
