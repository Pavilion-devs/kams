import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

const DOCS_HOST = "docs.usekams.xyz";

export function middleware(request: NextRequest) {
  const host = request.headers.get("host")?.split(":")[0].toLowerCase();

  if (host !== DOCS_HOST) {
    return NextResponse.next();
  }

  const { pathname } = request.nextUrl;

  // Keep documentation URLs clean on the docs subdomain:
  // docs.usekams.xyz/quickstart instead of docs.usekams.xyz/docs/quickstart.
  if (pathname === "/docs" || pathname.startsWith("/docs/")) {
    const cleanUrl = request.nextUrl.clone();
    cleanUrl.pathname = pathname.slice("/docs".length) || "/";
    return NextResponse.redirect(cleanUrl);
  }

  const docsUrl = request.nextUrl.clone();
  docsUrl.pathname = pathname === "/" ? "/docs" : `/docs${pathname}`;
  return NextResponse.rewrite(docsUrl);
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|apple-icon.png|icon.svg|media/).*)"],
};
