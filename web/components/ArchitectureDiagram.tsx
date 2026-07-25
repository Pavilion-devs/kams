type Props = {
  className?: string;
  /** Wrap in a light card (useful when placed on a dark background). */
  framed?: boolean;
};

/**
 * Responsive Kams architecture diagram.
 *
 * Renders the hand-authored SVG via <object> (so its embedded Inter @import
 * loads and it stays vector-crisp at any size), with the rendered PNG as a
 * graceful fallback. The aspect ratio is locked to the source artboard
 * (1644 x 1010) so it scales to any width with no layout shift.
 *
 * Source of truth for both assets is `docs/architecture/` in the repo root.
 * Copy `kams-architecture-diagram.{svg,png}` into `web/public/media/` as part
 * of the site build rather than keeping a second copy under version control.
 */
export default function ArchitectureDiagram({ className = "", framed = false }: Props) {
  return (
    <div
      className={[
        "w-full overflow-hidden",
        framed ? "rounded-2xl border border-zinc-200 bg-white shadow-2xl" : "",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
      style={{ aspectRatio: "1644 / 1010" }}
    >
      <object
        type="image/svg+xml"
        data="/media/kams-architecture-diagram.svg"
        aria-label="Kams architecture — SigNoz-native observability and containment for MCP"
        className="pointer-events-none block h-full w-full select-none"
      >
        <img
          src="/media/kams-architecture-diagram.png"
          alt="Kams architecture — SigNoz-native observability and containment for MCP"
          className="block h-full w-full"
        />
      </object>
    </div>
  );
}
