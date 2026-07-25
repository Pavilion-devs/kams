# Kams docs site

Next.js 14 + MDX documentation for [Kams](../README.md).

```bash
npm install
npm run dev     # http://localhost:3000 → redirects to /docs
npm run build   # static prerender of every docs route
npm start
```

## Layout

```text
app/
  layout.tsx            root shell, fonts, metadata
  icon.svg              favicon (modern browsers)
  favicon.ico           favicon (16/32/48 frames)
  apple-icon.png        180×180 touch icon
  page.tsx              / → /docs
  docs/
    layout.tsx          topbar + sidebar + article + TOC + prev/next
    page.mdx            Overview
    <section>/page.mdx  one file per docs page
components/
  KamsMark.tsx          the logo, same geometry as the favicon
  ArchitectureDiagram.tsx
  docs/                 Callout, CodeBlock, CodeGroup, Card, Steps, Toc, …
lib/
  docs-nav.ts           single source of truth for nav
  remark-code-meta.mjs  forwards ```lang title="…" onto the element
mdx-components.tsx      MDX element → component mapping
public/media/           architecture diagram (svg + png)
```

## Adding a page

1. Create `app/docs/<slug>/page.mdx` with an exported `metadata` object.
2. Add an entry to `docsNav` in `lib/docs-nav.ts`.

That array drives the sidebar, the ⌘K palette, **and** the prev/next footer, so a page can
never be reachable by one and invisible to the others.

## MDX components

Available in any `.mdx` file without importing:

| Component | Use |
|---|---|
| `<Callout type="note\|tip\|warning\|danger" title="…">` | Highlighted aside |
| `<CardGroup cols={1\|2\|3}>` + `<Card title icon href>` | Icon card grid |
| `<Steps>` + `<Step title="…">` | Numbered walkthrough |
| `<CodeGroup>` | Tabbed code blocks; labels come from fence `title="…"` |
| `<Eyebrow>` / `<Lede>` | Section kicker and page standfirst |
| `<ArchitectureDiagram framed />` | The architecture SVG |

Icons are [Iconify](https://icon-sets.iconify.design/) names, e.g. `solar:rocket-2-linear`.

## Assets

`public/media/kams-architecture-diagram.{svg,png}` are copies. The source of truth is
`../docs/architecture/`; re-copy after regenerating.
