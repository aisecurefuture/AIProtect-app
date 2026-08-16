import type { Metadata, Viewport } from "next";
import "./globals.css";
import Nav from "@/components/Nav";

export const metadata: Metadata = {
  title: "AIProtect",
  description: "AI security for your everyday devices.",
  icons: {
    icon: [
      { url: "/brand/icon-32.png", sizes: "32x32", type: "image/png" },
      { url: "/brand/icon-16.png", sizes: "16x16", type: "image/png" },
    ],
    apple: "/apple-touch-icon.png",
  },
};

// Mobile-first: this is the same UI on a phone, a tablet and a desktop.
export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-dvh">
        <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:m-2 focus:rounded focus:bg-brand-navy focus:px-3 focus:py-2 focus:text-white">
          Skip to content
        </a>
        <div className="mx-auto flex min-h-dvh w-full max-w-3xl flex-col">
          <main id="main" className="flex-1 px-4 pb-24 pt-6 sm:px-6">{children}</main>
          <Nav />
        </div>
      </body>
    </html>
  );
}
