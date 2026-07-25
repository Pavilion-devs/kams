"use client";

import {
  Children,
  cloneElement,
  isValidElement,
  useState,
  type ReactElement,
  type ReactNode,
} from "react";

/**
 * Tabbed set of code blocks. Each child is one fenced block; its tab label
 * comes from the `title` prop set on the fence (```bash title="stdio").
 * Falls back to the language, then to a positional label.
 */
export default function CodeGroup({ children }: { children: ReactNode }) {
  const blocks = Children.toArray(children).filter(isValidElement) as ReactElement[];
  const [active, setActive] = useState(0);

  if (blocks.length === 0) return null;

  const labelFor = (block: ReactElement, i: number): string => {
    const codeChild = block.props?.children as ReactElement | undefined;
    // `title` lands on the inner <code>, because that is the element
    // mdast-util-to-hast applies fence hProperties to.
    const title = block.props?.title ?? codeChild?.props?.title;
    if (typeof title === "string" && title) return title;
    const cls: string = codeChild?.props?.className ?? "";
    const m = /language-([\w-]+)/.exec(cls);
    return m ? m[1] : `Option ${i + 1}`;
  };

  return (
    <div className="my-5 overflow-hidden rounded-xl border border-zinc-200 dark:border-zinc-800">
      <div className="flex gap-1 overflow-x-auto border-b border-zinc-200 bg-zinc-50 px-2 py-1.5 dark:border-zinc-800 dark:bg-[#0f0f12]">
        {blocks.map((b, i) => (
          <button
            key={i}
            onClick={() => setActive(i)}
            className={`shrink-0 rounded-md px-3 py-1 text-[12.5px] font-medium transition-colors ${
              i === active
                ? "bg-white text-zinc-900 shadow-sm dark:bg-zinc-800 dark:text-white"
                : "text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white"
            }`}
          >
            {labelFor(b, i)}
          </button>
        ))}
      </div>
      {/* Strip the child's own border/rounding so it sits flush inside the frame. */}
      <div className="[&>div]:my-0 [&>div]:rounded-none [&>div]:border-0 [&>div>div]:border-t-0">
        {cloneElement(blocks[active], { inGroup: true })}
      </div>
    </div>
  );
}
