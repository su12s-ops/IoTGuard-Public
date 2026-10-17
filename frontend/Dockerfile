# LinuxGuard frontend — production image.
#
# The production image serves the built dist/ through nginx; the Vite dev
# server is never exposed. SPA route refresh works via try_files fallback,
# and /api is reverse-proxied to the backend service so the browser talks to
# a single origin (no cross-origin API base baked into the bundle).
FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm install --no-audit --no-fund

COPY index.html vite.config.js ./
COPY src ./src

# Relative /api base: nginx proxies /api to the backend container.
ARG VITE_API_BASE=/api
ENV VITE_API_BASE=$VITE_API_BASE
RUN npm run build

FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "--spider", "http://127.0.0.1/"]

CMD ["nginx", "-g", "daemon off;"]
