"use client";

import Link from "next/link";
import { Icon } from "@iconify/react";
import KamsMark from "@/components/KamsMark";
import ThemeToggle from "./ThemeToggle";
import SearchPalette from "./SearchPalette";

const openSearch = () => window.dispatchEvent(new Event("kams:open-search"));

export default function DocsTopbar() {
  return (
    <header className="sticky top-0 z-50 border-b border-zinc-200 bg-white/80 backdrop-blur-xl dark:border-zinc-800/70 dark:bg-[#0a0a0c]/80">
      <div className="mx-auto flex h-16 max-w-[1600px] items-center gap-3 px-4 lg:px-6">
        <Link href="/docs" className="flex items-center gap-2.5">
          <KamsMark className="h-8 w-8" />
          <span className="text-[15px] font-semibold tracking-tight text-zinc-900 dark:text-white">
            Kams <span className="text-zinc-400 dark:text-zinc-500">Docs</span>
          </span>
        </Link>

        <div className="flex-1" />

        <button
          onClick={openSearch}
          className="hidden items-center gap-2 rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-1.5 text-[13px] text-zinc-400 transition-colors hover:border-zinc-300 dark:border-zinc-800 dark:bg-zinc-900 dark:hover:border-zinc-700 sm:flex"
        >
          <Icon icon="solar:magnifer-linear" className="h-4 w-4" />
          Search
          <kbd className="ml-6 rounded border border-zinc-200 px-1.5 text-[10px] dark:border-zinc-700">
            ⌘K
          </kbd>
        </button>
        <button
          onClick={openSearch}
          aria-label="Search"
          className="grid h-9 w-9 place-items-center rounded-lg text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800 sm:hidden"
        >
          <Icon icon="solar:magnifer-linear" className="h-[18px] w-[18px]" />
        </button>

        <Link
          href="/docs/architecture"
          className="hidden text-[14px] font-medium text-zinc-600 transition-colors hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white md:block"
        >
          Architecture
        </Link>

        <ThemeToggle />

        <a
          href="https://github.com/Pavilion-devs/kams"
          target="_blank"
          rel="noreferrer"
          className="rounded-full bg-blue-600 px-4 py-1.5 text-[13px] font-medium text-white transition-colors hover:bg-blue-700"
        >
          GitHub
        </a>
      </div>
      <SearchPalette />
    </header>
  );
}
