import type { Metadata } from "next";
import DocsTopbar from "@/components/docs/DocsTopbar";
import DocsSidebar from "@/components/docs/DocsSidebar";
import Toc from "@/components/docs/Toc";
import PrevNext from "@/components/docs/PrevNext";

export const metadata: Metadata = {
  title: { default: "Kams Docs", template: "%s · Kams Docs" },
  description:
    "Documentation for Kams — SigNoz-native observability and closed-loop containment for the Model Context Protocol.",
};

// No-flash theme: run before the docs subtree paints. Defaults to light, which
// is what the architecture diagram is drawn for.
const themeScript = `(function(){try{var t=localStorage.getItem('kams-docs-theme');if(t==='dark'){document.documentElement.classList.add('dark');}else{document.documentElement.classList.remove('dark');}}catch(e){}})();`;

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-white text-zinc-900 dark:bg-[#0a0a0c] dark:text-zinc-100">
      <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      <DocsTopbar />
      <div className="mx-auto flex w-full max-w-[1600px]">
        <DocsSidebar />
        <main className="min-w-0 flex-1 px-6 py-10 lg:px-12">
          <article id="doc-article" className="mx-auto max-w-3xl">
            {children}
            <PrevNext />
          </article>
        </main>
        <Toc />
      </div>
    </div>
  );
}
