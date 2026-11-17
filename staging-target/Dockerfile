# Temporary staging target: the course's deliberately vulnerable API
# (pentest-worker/src/test-target.js), used until library-app is deployed.
# Build from the repo root:
#   docker build -f staging-target/Dockerfile -t staging-app .
FROM node:22-alpine
WORKDIR /app
COPY pentest-worker/src/package*.json ./
RUN npm ci --omit=dev
COPY pentest-worker/src/test-target.js ./
USER node
EXPOSE 4000
CMD ["node", "test-target.js"]
