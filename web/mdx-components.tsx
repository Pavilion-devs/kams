import type { MDXComponents } from "mdx/types";
import Link from "next/link";
import CodeBlock from "@/components/docs/CodeBlock";
import CodeGroup from "@/components/docs/CodeGroup";
import Callout from "@/components/docs/Callout";
import { Card, CardGroup } from "@/components/docs/Card";
import { Steps, Step } from "@/components/docs/Steps";
import ArchitectureDiagram from "@/components/ArchitectureDiagram";

const linkClass =
  "font-medium text-blue-600 underline decoration-blue-600/30 underline-offset-2 transition-colors hover:decoration-blue-600 dark:text-blue-400 dark:decoration-blue-400/30 dark:hover:decoration-blue-400";

export function useMDXComponents(components: MDXComponents): MDXComponents {
  return {
    h1: (p) => (
      <h1
        className="scroll-mt-24 text-3xl font-semibold tracking-tight text-zinc-900 md:text-[34px] dark:text-white"
        {...p}
      />
    ),
    h2: (p) => (
      <h2
        className="scroll-mt-24 mb-4 mt-12 border-t border-zinc-200 pt-8 text-[22px] font-semibold tracking-tight text-zinc-900 dark:border-zinc-800 dark:text-white"
        {...p}
      />
    ),
    h3: (p) => (
      <h3
        className="scroll-mt-24 mb-3 mt-8 text-lg font-semibold tracking-tight text-zinc-900 dark:text-zinc-100"
        {...p}
      />
    ),
    p: (p) => <p className="my-4 text-[15px] leading-7 text-zinc-600 dark:text-zinc-300" {...p} />,
    a: ({ href = "", ...p }) => {
      const internal = href.startsWith("/") || href.startsWith("#");
      return internal ? (
        <Link href={href} className={linkClass} {...p} />
      ) : (
        <a href={href} target="_blank" rel="noreferrer" className={linkClass} {...p} />
      );
    },
    ul: (p) => (
      <ul
        className="my-4 list-disc space-y-2 pl-5 text-[15px] leading-7 text-zinc-600 marker:text-zinc-400 dark:text-zinc-300"
        {...p}
      />
    ),
    ol: (p) => (
      <ol
        className="my-4 list-decimal space-y-2 pl-5 text-[15px] leading-7 text-zinc-600 marker:text-zinc-400 dark:text-zinc-300"
        {...p}
      />
    ),
    li: (p) => <li className="pl-1.5 [&>p]:my-0 [&>ul]:my-2 [&>ol]:my-2" {...p} />,
    strong: (p) => <strong className="font-semibold text-zinc-900 dark:text-white" {...p} />,
    hr: (p) => <hr className="my-10 border-zinc-200 dark:border-zinc-800" {...p} />,
    blockquote: (p) => (
      <blockquote
        className="my-5 border-l-2 border-blue-500/40 pl-4 italic text-zinc-600 dark:text-zinc-300"
        {...p}
      />
    ),
    table: (p) => (
      <div className="my-6 overflow-x-auto">
        <table className="w-full text-left text-sm" {...p} />
      </div>
    ),
    thead: (p) => <thead className="border-b border-zinc-300 dark:border-zinc-700" {...p} />,
    th: (p) => <th className="px-3 py-2 font-semibold text-zinc-900 dark:text-white" {...p} />,
    td: (p) => (
      <td
        className="border-b border-zinc-200 px-3 py-2 align-top text-zinc-600 dark:border-zinc-800 dark:text-zinc-300"
        {...p}
      />
    ),
    pre: (p) => <CodeBlock {...p} />,
    code: ({ className, ...p }: { className?: string }) =>
      className?.includes("language-") ? (
        <code className={className} {...p} />
      ) : (
        <code
          className="rounded-md border border-zinc-200 bg-zinc-100 px-1.5 py-0.5 font-mono text-[13px] text-blue-700 dark:border-zinc-700/60 dark:bg-zinc-800 dark:text-blue-300"
          {...p}
        />
      ),
    // Custom components available inside MDX:
    Eyebrow: (p: React.HTMLAttributes<HTMLParagraphElement>) => (
      <p
        className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400"
        {...p}
      />
    ),
    Lede: (p: React.HTMLAttributes<HTMLParagraphElement>) => (
      <p className="mb-8 mt-3 text-[17px] leading-8 text-zinc-500 dark:text-zinc-400" {...p} />
    ),
    Callout,
    Card,
    CardGroup,
    Steps,
    Step,
    CodeGroup,
    ArchitectureDiagram,
    ...components,
  };
}
