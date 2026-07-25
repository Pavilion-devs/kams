import Link from "next/link";
import type { ReactNode } from "react";
import { Icon } from "@iconify/react";

/**
 * Carry-style icon card. Becomes a link when `href` is given, a plain panel
 * otherwise, so the same component works for both "go here next" grids and
 * static feature grids.
 */
export function Card({
  title,
  icon,
  href,
  children,
}: {
  title: string;
  icon?: string;
  href?: string;
  children?: ReactNode;
}) {
  const inner = (
    <>
      {icon && (
        <span className="mb-3 grid h-9 w-9 place-items-center rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400">
          <Icon icon={icon} className="h-[19px] w-[19px]" />
        </span>
      )}
      <p className="text-[15px] font-semibold tracking-tight text-zinc-900 dark:text-white">
        {title}
      </p>
      {children && (
        <div className="mt-1.5 text-[13.5px] leading-6 text-zinc-600 dark:text-zinc-400 [&>p]:m-0">
          {children}
        </div>
      )}
    </>
  );

  const base =
    "flex flex-col rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-zinc-900/40";

  if (!href) return <div className={base}>{inner}</div>;

  const internal = href.startsWith("/") || href.startsWith("#");
  const cls = `${base} transition-colors hover:border-blue-400/60 hover:bg-blue-500/[0.03] dark:hover:border-blue-500/40`;

  return internal ? (
    <Link href={href} className={cls}>
      {inner}
    </Link>
  ) : (
    <a href={href} target="_blank" rel="noreferrer" className={cls}>
      {inner}
    </a>
  );
}

/** Responsive grid wrapper. `cols` is the desktop column count. */
export function CardGroup({ cols = 2, children }: { cols?: 1 | 2 | 3; children: ReactNode }) {
  const grid =
    cols === 1 ? "sm:grid-cols-1" : cols === 3 ? "sm:grid-cols-2 lg:grid-cols-3" : "sm:grid-cols-2";
  return <div className={`my-6 grid grid-cols-1 gap-4 ${grid}`}>{children}</div>;
}

export default Card;
