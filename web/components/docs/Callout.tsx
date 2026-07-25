"use client";

import { Icon } from "@iconify/react";
import type { ReactNode } from "react";

type CalloutType = "note" | "tip" | "warning" | "danger";

const VARIANTS: Record<CalloutType, { icon: string; ring: string; tint: string; mark: string }> = {
  note: {
    icon: "solar:info-circle-linear",
    ring: "border-blue-500/30",
    tint: "bg-blue-500/[0.06]",
    mark: "text-blue-500 dark:text-blue-400",
  },
  tip: {
    icon: "solar:lightbulb-bolt-linear",
    ring: "border-emerald-500/30",
    tint: "bg-emerald-500/[0.06]",
    mark: "text-emerald-500 dark:text-emerald-400",
  },
  warning: {
    icon: "solar:danger-triangle-linear",
    ring: "border-amber-500/30",
    tint: "bg-amber-500/[0.06]",
    mark: "text-amber-500 dark:text-amber-400",
  },
  danger: {
    icon: "solar:shield-warning-linear",
    ring: "border-red-500/30",
    tint: "bg-red-500/[0.06]",
    mark: "text-red-500 dark:text-red-400",
  },
};

export default function Callout({
  type = "note",
  title,
  children,
}: {
  type?: CalloutType;
  title?: string;
  children: ReactNode;
}) {
  const v = VARIANTS[type];
  return (
    <div className={`my-5 flex gap-3 rounded-xl border ${v.ring} ${v.tint} px-4 py-3.5`}>
      <Icon icon={v.icon} className={`mt-0.5 h-5 w-5 shrink-0 ${v.mark}`} />
      <div className="min-w-0 text-[14px] leading-relaxed text-zinc-700 dark:text-zinc-300 [&>p]:m-0 [&>p+p]:mt-2">
        {title && <p className="mb-1 font-semibold text-zinc-900 dark:text-white">{title}</p>}
        {children}
      </div>
    </div>
  );
}
