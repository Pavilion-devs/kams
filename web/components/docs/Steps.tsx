import { Children, isValidElement, type ReactNode } from "react";

/**
 * Numbered walkthrough. The connecting rule is drawn by the container rather
 * than each step, so the last step does not trail a dangling line.
 */
export function Steps({ children }: { children: ReactNode }) {
  const steps = Children.toArray(children).filter(isValidElement);
  return (
    <div className="my-6">
      {steps.map((step, i) => (
        <div key={i} className="relative flex gap-4 pb-8 last:pb-0">
          {i < steps.length - 1 && (
            <span
              aria-hidden
              className="absolute left-[15px] top-9 bottom-0 w-px bg-zinc-200 dark:bg-zinc-800"
            />
          )}
          <span className="relative z-10 grid h-8 w-8 shrink-0 place-items-center rounded-full border border-zinc-200 bg-white text-[13px] font-semibold text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-white">
            {i + 1}
          </span>
          <div className="min-w-0 flex-1 pt-0.5">{step}</div>
        </div>
      ))}
    </div>
  );
}

export function Step({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <>
      <p className="m-0 text-[15px] font-semibold tracking-tight text-zinc-900 dark:text-white">
        {title}
      </p>
      <div className="[&>*:first-child]:mt-2 [&>*:last-child]:mb-0">{children}</div>
    </>
  );
}

export default Steps;
