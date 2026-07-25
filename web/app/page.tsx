import { redirect } from "next/navigation";

/** No marketing surface yet — the docs are the product site. */
export default function Home() {
  redirect("/docs");
}
