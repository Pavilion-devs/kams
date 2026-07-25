import createMDX from "@next/mdx";
import remarkGfm from "remark-gfm";
import rehypeSlug from "rehype-slug";
import remarkCodeMeta from "./lib/remark-code-meta.mjs";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Allow .md/.mdx files to be treated as routes/pages (docs live in app/docs/**).
  pageExtensions: ["ts", "tsx", "js", "jsx", "md", "mdx"],
};

const withMDX = createMDX({
  options: {
    remarkPlugins: [remarkGfm, remarkCodeMeta],
    // Gives every heading an id, which is what the "On this page" rail reads.
    rehypePlugins: [rehypeSlug],
  },
});

export default withMDX(nextConfig);
