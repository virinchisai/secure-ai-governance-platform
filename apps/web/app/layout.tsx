import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis | Secure AI Governance",
  description: "Local-first enterprise AI security and governance reference platform",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
