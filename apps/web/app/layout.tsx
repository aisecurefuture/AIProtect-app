import type { Metadata, Viewport } from "next";
import "./globals.css";
import Nav from "@/components/Nav";

export const metadata: Metadata = {
  title: "AIProtect",
  description: "AI security for your everyday devices.",
};

// Mobile-first: this is the same UI on a phone, a tablet and a desktop.
export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-dvh">
        <div className="mx-auto flex min-h-dvh w-full max-w-3xl flex-col">
          <main id="main" className="flex-1 px-4 pb-24 pt-6 sm:px-6">{children}</main>
          <Nav />
        </div>
      </body>
    </html>
  );
}
