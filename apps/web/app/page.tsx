"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { getToken } from "@/lib/api";

export default function Index() {
  const router = useRouter();
  useEffect(() => {
    router.replace(getToken() ? "/home" : "/signin");
  }, [router]);
  return <p className="text-sm opacity-70">Loading…</p>;
}
