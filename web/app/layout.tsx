import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL("https://www.usekams.xyz"),
  title: {
    default: "Kams — SigNoz-native observability and containment for MCP",
    template: "%s · Kams",
  },
  description:
    "Kams sits transparently between an agent and its MCP servers: it emits OpenTelemetry MCP traces, metrics and correlated logs to SigNoz, pins every tool definition, detects drift, injection, sensitive egress and context cost, then turns a SigNoz alert into a TTL-bound quarantine before the next tool call.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}
