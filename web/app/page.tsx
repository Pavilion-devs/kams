import KamsMark from "@/components/KamsMark";

export default function Home() {
  return (
    <main className="relative flex min-h-screen overflow-hidden bg-[#f7f7f3] text-zinc-950">
      <div
        aria-hidden="true"
        className="absolute inset-0 bg-[linear-gradient(to_right,rgba(24,24,27,0.055)_1px,transparent_1px),linear-gradient(to_bottom,rgba(24,24,27,0.055)_1px,transparent_1px)] bg-[size:52px_52px] [mask-image:radial-gradient(ellipse_78%_70%_at_50%_45%,#000_35%,transparent_100%)]"
      />
      <div
        aria-hidden="true"
        className="absolute left-1/2 top-1/2 h-[34rem] w-[34rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-blue-200/30 blur-3xl"
      />

      <div className="relative z-10 flex min-h-screen w-full flex-col px-6 py-6 sm:px-10 sm:py-8 lg:px-14">
        <header className="flex items-center justify-between">
          <a href="/" className="flex items-center gap-3" aria-label="Kams home">
            <KamsMark className="h-9 w-9" />
            <span className="text-lg font-semibold tracking-[-0.03em]">Kams</span>
          </a>

          <nav className="flex items-center gap-5 text-sm font-medium text-zinc-600">
            <a className="transition-colors hover:text-zinc-950" href="/architecture">
              Architecture
            </a>
            <a
              className="transition-colors hover:text-zinc-950"
              href="https://github.com/Pavilion-devs/kams"
              target="_blank"
              rel="noreferrer"
            >
              GitHub
            </a>
          </nav>
        </header>

        <section className="mx-auto flex w-full max-w-5xl flex-1 flex-col items-center justify-center py-20 text-center">
          <p className="mb-7 font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-blue-700 sm:text-xs">
            Open source · MCP trust and enforcement
          </p>

          <h1 className="max-w-5xl text-balance text-[clamp(2.45rem,5.2vw,4.8rem)] font-semibold leading-[0.98] tracking-[-0.055em]">
            SigNoz-native observability and closed-loop containment for the Model Context
            Protocol.
          </h1>

          <p className="mt-8 max-w-2xl text-pretty text-base leading-7 text-zinc-600 sm:text-lg">
            Observe every MCP boundary, detect trust drift, and turn alerts into policy
            before the next unsafe tool call runs.
          </p>

          <div className="mt-10 flex w-full max-w-md flex-col gap-3 sm:flex-row sm:justify-center">
            <a
              href="https://youtu.be/2A5t79Ryufc"
              target="_blank"
              rel="noreferrer"
              className="inline-flex min-h-12 flex-1 items-center justify-center rounded-full bg-zinc-950 px-6 text-sm font-semibold text-white shadow-[0_12px_30px_rgba(24,24,27,0.16)] transition-transform hover:-translate-y-0.5"
            >
              Watch demo
            </a>
            <a
              href="https://docs.usekams.xyz/"
              className="inline-flex min-h-12 flex-1 items-center justify-center rounded-full border border-zinc-300 bg-white/80 px-6 text-sm font-semibold text-zinc-900 backdrop-blur transition-colors hover:border-zinc-500 hover:bg-white"
            >
              Explore docs
            </a>
          </div>
        </section>

        <footer className="flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-500 sm:text-[11px]">
          <span>Kams × SigNoz</span>
          <span>Observe · Detect · Contain</span>
        </footer>
      </div>
    </main>
  );
}
