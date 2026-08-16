import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Static export: the whole site becomes files Caddy serves directly. No Node
  // process on the box, which matters because this shares a host with a
  // paying customer's stack.
  output: "export",
  images: { unoptimized: true },
};
export default nextConfig;
