import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Standalone traces only the files actually imported, so the runtime image
  // carries a few MB of app instead of the whole node_modules tree.
  output: "standalone",
};

export default nextConfig;
