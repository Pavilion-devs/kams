"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Icon } from "@iconify/react";
import { flatDocs } from "@/lib/docs-nav";

export default function PrevNext() {
  const pathname = usePathname();
  const idx = flatDocs.findIndex((d) => d.slug === pathname);
  if (idx === -1) return null;
  const prev = idx > 0 ? flatDocs[idx - 1] : null;
  const next = idx < flatDocs.length - 1 ? flatDocs[idx + 1] : null;

  return (
    <nav className="mt-16 grid grid-cols-2 gap-4 border-t border-zinc-200 pt-8 dark:border-zinc-800">
      <div>
        {prev && (
          <Link
            href={prev.slug}
            className="flex flex-col rounded-xl border border-zinc-200 p-4 transition-colors hover:border-zinc-300 dark:border-zinc-800 dark:hover:border-zinc-700"
          >
            <span className="flex items-center gap-1 text-[12px] text-zinc-400">
              <Icon icon="solar:arrow-left-linear" className="h-3.5 w-3.5" /> Previous
            </span>
            <span className="mt-1 text-[14px] font-medium text-zinc-900 dark:text-white">
              {prev.title}
            </span>
          </Link>
        )}
      </div>
      <div>
        {next && (
          <Link
            href={next.slug}
            className="flex flex-col items-end rounded-xl border border-zinc-200 p-4 text-right transition-colors hover:border-zinc-300 dark:border-zinc-800 dark:hover:border-zinc-700"
          >
            <span className="flex items-center gap-1 text-[12px] text-zinc-400">
              Next <Icon icon="solar:arrow-right-linear" className="h-3.5 w-3.5" />
            </span>
            <span className="mt-1 text-[14px] font-medium text-zinc-900 dark:text-white">
              {next.title}
            </span>
          </Link>
        )}
      </div>
    </nav>
  );
}
