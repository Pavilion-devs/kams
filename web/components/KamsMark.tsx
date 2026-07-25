/**
 * The Kams mark: a stem (the boundary) and a chevron (the traffic that has to
 * pass through it). Reads as a K at wordmark size, as an interception point
 * everywhere else. Same geometry as the `#logo` symbol in the architecture SVG
 * and the favicon, so all three stay identical.
 */
export default function KamsMark({ className = "h-8 w-8" }: { className?: string }) {
  return (
    <svg viewBox="0 0 122 122" className={className} role="img" aria-label="Kams">
      <defs>
        <linearGradient id="kamsMarkGrad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#172554" />
          <stop offset="0.5" stopColor="#2563eb" />
          <stop offset="1" stopColor="#60a5fa" />
        </linearGradient>
      </defs>
      <rect x="0" y="0" width="122" height="122" rx="28" fill="url(#kamsMarkGrad)" />
      <rect x="32" y="27" width="9" height="68" rx="4.5" fill="#ffffff" />
      <path
        d="M54 27 L88 61 L54 95"
        fill="none"
        stroke="#ffffff"
        strokeWidth="9"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
