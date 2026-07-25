export type DocPage = {
  title: string;
  slug: string;
  summary: string;
};

export type DocGroup = {
  title: string;
  items: DocPage[];
};

/** Sidebar structure. Drives the sidebar, ⌘K search, and prev/next footer. */
export const docsNav: DocGroup[] = [
  {
    title: "Getting started",
    items: [
      {
        title: "Overview",
        slug: "/docs",
        summary:
          "What Kams is: an observable dependency boundary between an agent and its MCP servers.",
      },
      {
        title: "Quickstart",
        slug: "/docs/quickstart",
        summary: "Bootstrap SigNoz, run the deterministic rug pull, and watch the loop close.",
      },
      {
        title: "Installation & setup",
        slug: "/docs/setup",
        summary: "Docker, Python and uv, the Foundry deployment, and the SigNoz API key.",
      },
    ],
  },
  {
    title: "Core concepts",
    items: [
      {
        title: "How Kams works",
        slug: "/docs/how-it-works",
        summary: "Intercept, observe, detect, alert, contain — the five steps end to end.",
      },
      {
        title: "Tool-definition integrity",
        slug: "/docs/integrity",
        summary: "Pinning, kams.lock, drift classification, and deterministic injection scoring.",
      },
      {
        title: "The control loop",
        slug: "/docs/control-loop",
        summary: "Two paths write one restriction shape: the local reflex and the SigNoz alert.",
      },
    ],
  },
  {
    title: "Detectors",
    items: [
      {
        title: "Integrity & injection",
        slug: "/docs/detectors/integrity",
        summary: "Description drift, schema widening, homoglyph squatting, and result injection.",
      },
      {
        title: "Egress, cost & behaviour",
        slug: "/docs/detectors/egress-cost-behaviour",
        summary: "Sensitive classes, context-cost attribution, and reliability checks.",
      },
    ],
  },
  {
    title: "Policy",
    items: [
      {
        title: "policy.yaml reference",
        slug: "/docs/policy",
        summary: "Ordered rules, matchers, actions, TTLs, and sliding-window rate limits.",
      },
      {
        title: "Shared state & TTL",
        slug: "/docs/shared-state",
        summary: "The cross-process restriction file, atomic writes, and fail-open reads.",
      },
    ],
  },
  {
    title: "Integrations",
    items: [
      {
        title: "stdio shim",
        slug: "/docs/integrations/stdio",
        summary: "Wrap any stdio MCP server with a one-line change to your agent config.",
      },
      {
        title: "Streamable HTTP",
        slug: "/docs/integrations/http",
        summary: "Reverse-proxy an HTTP MCP endpoint through the same detector pipeline.",
      },
      {
        title: "SigNoz",
        slug: "/docs/integrations/signoz",
        summary: "The nine-panel dashboard, the critical alert, and the webhook that contains.",
      },
    ],
  },
  {
    title: "Reference",
    items: [
      {
        title: "CLI reference",
        slug: "/docs/cli",
        summary: "shim, proxy, pin, status, and daemon — every command and flag.",
      },
      {
        title: "Telemetry & semconv",
        slug: "/docs/telemetry",
        summary: "Span names, attributes, metrics, and SEP-414 trace propagation.",
      },
    ],
  },
  {
    title: "Resources",
    items: [
      {
        title: "Architecture",
        slug: "/docs/architecture",
        summary: "The full Kams runtime topology, in one diagram.",
      },
    ],
  },
];

/** Flattened, ordered list for prev/next navigation and search. */
export const flatDocs = docsNav.flatMap((group) =>
  group.items.map((item) => ({ ...item, group: group.title })),
);
