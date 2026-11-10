// DoubleCheck - webhook intake Lambda
// Verifies GitHub's signature, then queues a SAST job for every opened/updated PR.
// (Next: set the PR status to pending + record jobs in DynamoDB.)

import crypto from "node:crypto";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";

const sm = new SecretsManagerClient({});
const sqs = new SQSClient({});
let cachedSecret; // reused while the Lambda stays warm

async function getSecret() {
  if (!cachedSecret) {
    const out = await sm.send(new GetSecretValueCommand({ SecretId: process.env.SECRET_ID }));
    cachedSecret = out.SecretString;
  }
  return cachedSecret;
}

// GitHub signs the raw body with HMAC-SHA256 using the shared secret
function validSignature(secret, rawBody, header) {
  if (!header || !header.startsWith("sha256=")) return false;
  const expected = "sha256=" + crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(header);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const reply = (statusCode, message) => ({
  statusCode,
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ message }),
});

export const handler = async (event) => {
  const headers = event.headers || {}; // HTTP API lowercases header names
  const rawBody = Buffer.from(event.body || "", event.isBase64Encoded ? "base64" : "utf8");
  const deliveryId = headers["x-github-delivery"];

  // 1. Reject anything not signed with our secret
  const secret = await getSecret();
  if (!validSignature(secret, rawBody, headers["x-hub-signature-256"])) {
    console.warn("Rejected: invalid signature", { deliveryId });
    return reply(401, "invalid signature");
  }

  const eventType = headers["x-github-event"];
  const payload = JSON.parse(rawBody.toString("utf8"));

  // 2. GitHub's test message when the webhook is first added
  if (eventType === "ping") {
    console.log("Ping received", { deliveryId, hookId: payload.hook_id });
    return reply(200, "pong");
  }

  // 3. Pull request events
  if (eventType === "pull_request") {
    const pr = payload.pull_request;
    const info = {
      deliveryId,
      action: payload.action,
      repo: payload.repository.full_name,
      pr: pr.number,
      commitSha: pr.head.sha,
      branch: pr.head.ref,
      baseBranch: pr.base.ref,
    };

    if (["opened", "synchronize", "reopened"].includes(payload.action)) {
      // Job message: format from docs/contracts.md section 1a
      const job = {
        schemaVersion: 1,
        jobId: crypto.randomUUID(),
        scanType: "sast",
        repo: info.repo,
        pr: info.pr,
        commitSha: info.commitSha,
        branch: info.branch,
        baseBranch: info.baseBranch,
        trigger: "pull_request." + payload.action,
        deliveryId,
        requestedAt: new Date().toISOString(),
      };
      await sqs.send(new SendMessageCommand({ QueueUrl: process.env.QUEUE_URL, MessageBody: JSON.stringify(job) }));
      console.log("SAST job queued", job);
      return reply(202, "scan accepted");
    }

    if (payload.action === "closed" && pr.merged) {
      console.log("PR merged", { ...info, mergeCommitSha: pr.merge_commit_sha }); // next: Merges table
      return reply(200, "merge recorded");
    }
  }

  // 4. Everything else
  console.log("Ignored event", { eventType, action: payload.action, deliveryId });
  return reply(200, "ignored");
};
