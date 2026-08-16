"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";

const ITEMS = [
  { href: "/home", label: "Home" },
  { href: "/links", label: "Links" },
  { href: "/privacy", label: "Privacy" },
  { href: "/devices", label: "Devices" },
  { href: "/settings", label: "Settings" },
];

/** Bottom bar on phones, top bar from `sm` up. One component, both shapes. */
export default function Nav() {
  const path = usePathname();
  if (path === "/" || path === "/signin") return null;
  return (
    <nav
      aria-label="Main"
      className="fixed inset-x-0 bottom-0 border-t border-slate-200 bg-white/95 backdrop-blur dark:border-slate-800 dark:bg-slate-950/95 sm:static sm:border-b sm:border-t-0"
    >
      <ul className="mx-auto flex max-w-3xl">
        {ITEMS.map((item) => {
          const active = path.startsWith(item.href);
          return (
            <li key={item.href} className="flex-1">
              <Link
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`flex min-h-14 items-center justify-center text-sm font-medium ${
                  active
                    ? "text-blue-600 dark:text-blue-400"
                    : "text-slate-500 dark:text-slate-400"
                }`}
              >
                {item.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
