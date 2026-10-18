# LinuxGuard frontend — production image.
#
# The production image serves the built dist/ through nginx; the Vite dev
# server is never exposed. SPA route refresh works via try_files fallback,
# and /api is reverse-proxied to the backend service so the browser talks to
# a single origin (no cross-origin API base baked into the bundle).
FROM node:24-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci --no-audit --no-fund

COPY index.html vite.config.js ./
COPY src ./src

# Relative /api base: nginx proxies /api to the backend container.
ARG VITE_API_BASE=/api
ENV VITE_API_BASE=$VITE_API_BASE
RUN npm run build

FROM nginx:stable-alpine
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.revision=$VCS_REF org.opencontainers.image.created=$BUILD_DATE

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
RUN sed -i -e 's@/var/run/nginx.pid@/tmp/nginx.pid@' -e 's@/run/nginx.pid@/tmp/nginx.pid@' -e '/^user /d' /etc/nginx/nginx.conf \
    && chown -R nginx:nginx /var/cache/nginx /etc/nginx/conf.d
USER nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "--spider", "http://127.0.0.1:8080/"]

CMD ["nginx", "-g", "daemon off;"]
