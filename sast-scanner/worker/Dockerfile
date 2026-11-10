# DoubleCheck - SAST scanner + worker image
FROM node:20-alpine

# Course scanner (unchanged)
WORKDIR /app
COPY src/package*.json ./
RUN npm ci --omit=dev
COPY src/ ./

# DoubleCheck worker (pulls jobs from SQS, calls the scanner)
WORKDIR /worker
COPY worker/package.json ./
RUN npm install --omit=dev
COPY worker/worker.js ./

# Run as the built-in non-root "node" user
USER node
ENV NODE_ENV=production
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget -qO- http://localhost:3000/health || exit 1

# The worker starts the scanner server, then polls SQS
CMD ["node", "/worker/worker.js"]
