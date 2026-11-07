# NetSec Board. Zero npm runtime dependencies; node:sqlite is stable on Node 24.
# Pin by digest for production: docker pull node:24-bookworm-slim && docker inspect --format '{{index .RepoDigests 0}}'
FROM node:24-bookworm-slim
ENV NODE_ENV=production NETSEC_CONFIG=/config/netsec.json
WORKDIR /app
COPY package.json LICENSE netsec.example.json manual.html ./
COPY src ./src
COPY server ./server
COPY cli ./cli
COPY board ./board
COPY mocks ./mocks
COPY samples ./samples
COPY scripts ./scripts
COPY deploy ./deploy
RUN mkdir -p /data /config /backups && chown node:node /data /config
USER node
VOLUME ["/data"]
EXPOSE 8480 5514/tcp 5514/udp
# the config must listen on 0.0.0.0:8480 inside the container (compose publishes it on 127.0.0.1 only)
HEALTHCHECK --interval=30s --timeout=5s CMD ["node", "-e", "fetch('http://127.0.0.1:8480/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "server/main.js"]
