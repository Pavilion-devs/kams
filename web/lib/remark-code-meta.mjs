import { visit } from "unist-util-visit";

/**
 * Forwards fence metadata onto the rendered element.
 *
 *     ```bash title="Shell"
 *
 * MDX parses that trailing string into `node.meta` but drops it on the way to
 * hast, so without this the tab labels in <CodeGroup> and the header in
 * <CodeBlock> can only ever show the language.
 */
export default function remarkCodeMeta() {
  return (tree) => {
    visit(tree, "code", (node) => {
      if (!node.meta) return;
      const match = /title="([^"]*)"/.exec(node.meta);
      if (!match) return;
      node.data = node.data || {};
      node.data.hProperties = { ...(node.data.hProperties || {}), title: match[1] };
    });
  };
}
