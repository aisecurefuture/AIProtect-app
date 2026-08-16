# Build
FROM node:22-slim AS build
WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
# Baked at BUILD time: NEXT_PUBLIC_* is inlined into the client bundle, so
# setting it only in compose `environment:` would leave the browser calling
# whatever the default was when the image was built.
ARG NEXT_PUBLIC_API_URL=https://api.aiprotect.app
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
RUN npm run build

# Run
FROM node:22-slim AS run
WORKDIR /app
ENV NODE_ENV=production PORT=3000 HOSTNAME=0.0.0.0
COPY --from=build /app/public ./public
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
RUN useradd --create-home --shell /usr/sbin/nologin appuser && chown -R appuser /app
USER appuser
EXPOSE 3000
CMD ["node", "server.js"]
