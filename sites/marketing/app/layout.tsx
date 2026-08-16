import type { Metadata, Viewport } from "next";
import "./globals.css";

const DESC =
  "AIProtect checks links before you open them and warns you before you share " +
  "personal information with an AI assistant. For your phone, tablet and computer.";

export const metadata: Metadata = {
  metadataBase: new URL("https://aiprotect.app"),
  title: "AIProtect — AI security for your everyday devices",
  description: DESC,
  openGraph: {
    title: "AIProtect", description: DESC, url: "https://aiprotect.app",
    siteName: "AIProtect", images: ["/lockup-on-dark.png"], type: "website",
  },
  twitter: { card: "summary_large_image", title: "AIProtect", description: DESC },
  icons: { icon: "/icon-32.png", apple: "/icon-180.png" },
};

export const viewport: Viewport = {
  width: "device-width", initialScale: 1, themeColor: "#080b14",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-dvh">
        <a href="#main"
           className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-3 focus:rounded focus:bg-white focus:px-4 focus:py-2 focus:text-slate-900">
          Skip to content
        </a>
        {children}
      </body>
    </html>
  );
}
