"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";

type Heading = { id: string; text: string; level: number };

/** Builds the "On this page" rail from the rendered article headings. */
export default function Toc() {
  const pathname = usePathname();
  const [items, setItems] = useState<Heading[]>([]);
  const [active, setActive] = useState("");

  useEffect(() => {
    const article = document.getElementById("doc-article");
    if (!article) return;
    const els = Array.from(article.querySelectorAll("h2, h3")).filter(
      (e) => (e as HTMLElement).id,
    ) as HTMLElement[];
    setItems(els.map((e) => ({ id: e.id, text: e.innerText, level: e.tagName === "H3" ? 3 : 2 })));

    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((en) => {
          if (en.isIntersecting) setActive((en.target as HTMLElement).id);
        });
      },
      { rootMargin: "-80px 0px -70% 0px" },
    );
    els.forEach((e) => obs.observe(e));
    return () => obs.disconnect();
    // Re-scan on navigation: the article subtree is replaced, not remounted.
  }, [pathname]);

  if (items.length === 0) return null;

  return (
    <aside className="sticky top-16 hidden h-[calc(100vh-4rem)] w-56 shrink-0 overflow-y-auto py-10 pr-6 xl:block">
      <p className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
        On this page
      </p>
      <ul className="space-y-1.5">
        {items.map((h) => (
          <li key={h.id} className={h.level === 3 ? "ml-3" : ""}>
            <a
              href={`#${h.id}`}
              className={`block border-l-2 pl-3 text-[13px] leading-snug transition-colors ${
                active === h.id
                  ? "border-blue-500 text-blue-600 dark:text-blue-400"
                  : "border-transparent text-zinc-500 hover:text-zinc-900 dark:text-zinc-500 dark:hover:text-zinc-200"
              }`}
            >
              {h.text}
            </a>
          </li>
        ))}
      </ul>
    </aside>
  );
}
