// DoubleCheck - SAST worker
// Pulls SAST jobs from SQS, downloads the PR's code at the exact commit,
// scans it with the course scanner (POST /scan/directory), sets the PR status
// and posts (or updates) one PR comment with masked findings.
// (Next: thresholds from .security-gate.yml, S3/DynamoDB results.)

import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from "@aws-sdk/client-sqs";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

const exec = promisify(execFile);
const QUEUE_URL = process.env.QUEUE_URL;
const TOKEN_SECRET_ID = process.env.TOKEN_SECRET_ID || "doublecheck/github-token";
const STATUS_CONTEXT = "DoubleCheck / SAST";
const COMMENT_MARKER = "<!-- doublecheck:sast -->"; // finds our own comment again
const MAX_LISTED = 25; // findings shown in the comment
const MAX_ATTEMPTS = 3; // must match the queue's maxReceiveCount
const SCANNER_URL = process.env.SCANNER_URL || "http://127.0.0.1:3000"; // IPv4: "localhost" can resolve to IPv6 and hang

const sqs = new SQSClient({});
const sm = new SecretsManagerClient({});
let running = true;
let token;

// 1. Start the course scanner server in the same container
const server = spawn("npm", ["start"], { cwd: "/app", stdio: "inherit" });
server.on("exit", (code) => {
  console.error(`Scanner server exited (code ${code}); stopping worker`);
  process.exit(1);
});

async function waitForScanner() {
  console.log("Waiting for scanner server at", SCANNER_URL);
  for (let i = 1; i <= 30; i++) {
    try {
      const r = await fetch(`${SCANNER_URL}/health`, { signal: AbortSignal.timeout(2000) });
      if (r.ok) return console.log("Scanner server is healthy");
    } catch (err) {
      console.log(`Health check ${i}/30 not ready yet: ${err.cause?.code || err.name}`);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error("Scanner server did not become healthy");
}

// 2. GitHub token from Secrets Manager (cached)
async function getToken() {
  if (!token) {
    const out = await sm.send(new GetSecretValueCommand({ SecretId: TOKEN_SECRET_ID }));
    token = out.SecretString.trim();
  }
  return token;
}

// Small GitHub API helper
async function github(method, apiPath, body) {
  const res = await fetch(`https://api.github.com${apiPath}`, {
    method,
    headers: {
      Authorization: `Bearer ${await getToken()}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "doublecheck-sast-worker",
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`GitHub ${method} ${apiPath} -> ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res.status === 204 ? null : res.json();
}

// Sets the commit status shown on the PR (pending / success / failure / error)
async function setStatus(repo, sha, state, description) {
  await github("POST", `/repos/${repo}/statuses/${sha}`,
    { state, context: STATUS_CONTEXT, description: description.slice(0, 140) });
}

// ---------- PR comment ----------
const SEVERITY_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2 };

// Secret-type findings: keep the first 2 characters of any quoted value, mask the rest
function maskEvidence(finding) {
  const text = String(finding.evidence || "").trim();
  if (!/SECRET|SENSITIVE|PASSWORD|TOKEN|KEY|CREDENTIAL/i.test(String(finding.id))) return text;
  return text.replace(/(["'`])([^"'`]{0,200})\1/g, (m, q, val) =>
    val.length <= 2 ? m : `${q}${val.slice(0, 2)}****${q}`);
}

// Keep table cells on one line and stop them breaking the markdown
const cell = (t) => String(t ?? "").replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();
const code = (t) => "`" + cell(t).replace(/`/g, "'").slice(0, 100) + "`";

function buildComment(job, { state, counts, vulns, filesScanned, durationMs, codeDir }) {
  const short = job.commitSha.slice(0, 7);
  const head = state === "failure" ? "❌ **DoubleCheck SAST: merge blocked**"
    : vulns.length ? "⚠️ **DoubleCheck SAST: passed with warnings**"
    : "✅ **DoubleCheck SAST: no issues found**";
  const lines = [
    COMMENT_MARKER,
    head,
    "",
    `**${counts.HIGH} HIGH** · **${counts.MEDIUM} MEDIUM** · **${counts.LOW} LOW** in ${filesScanned ?? "?"} files · commit \`${short}\` · ${(durationMs / 1000).toFixed(1)}s`,
    "",
  ];
  if (vulns.length) {
    const sorted = [...vulns].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
    lines.push("| Severity | Rule | Location | Evidence | Fix |", "| --- | --- | --- | --- | --- |");
    for (const v of sorted.slice(0, MAX_LISTED)) {
      const rel = path.isAbsolute(String(v.file)) ? path.relative(codeDir, v.file) : String(v.file);
      const link = `[${cell(rel)}:${v.line}](https://github.com/${job.repo}/blob/${job.commitSha}/${rel}#L${v.line})`;
      lines.push(`| ${v.severity} | ${cell(v.id)} | ${link} | ${code(maskEvidence(v))} | ${cell(v.message || v.description)} |`);
    }
    if (sorted.length > MAX_LISTED) lines.push("", `…and **${sorted.length - MAX_LISTED} more** findings.`);
  }
  lines.push("", `<sub>Rule: block on HIGH (default). Updated on every push; secrets are masked.</sub>`);
  return lines.join("\n");
}

// One comment per PR: edit ours if it exists, otherwise create it
async function upsertComment(repo, pr, body) {
  const comments = await github("GET", `/repos/${repo}/issues/${pr}/comments?per_page=100`);
  const mine = comments.find((c) => c.body && c.body.includes(COMMENT_MARKER));
  if (mine) {
    await github("PATCH", `/repos/${repo}/issues/comments/${mine.id}`, { body });
    return "updated";
  }
  await github("POST", `/repos/${repo}/issues/${pr}/comments`, { body });
  return "created";
}

// 3a. Download + unpack the repo at the job's commit
async function downloadCode(repo, commitSha) {
  const res = await fetch(`https://api.github.com/repos/${repo}/tarball/${commitSha}`, {
    headers: {
      Authorization: `Bearer ${await getToken()}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "doublecheck-sast-worker",
    },
  });
  if (!res.ok) throw new Error(`GitHub download failed: ${res.status} ${res.statusText}`);

  const workDir = await mkdtemp(path.join(tmpdir(), "scan-"));
  const archive = path.join(workDir, "code.tar.gz");
  const codeDir = path.join(workDir, "code");
  await writeFile(archive, Buffer.from(await res.arrayBuffer()));
  await mkdir(codeDir);
  await exec("tar", ["-xzf", archive, "-C", codeDir, "--strip-components=1"]);
  return { workDir, codeDir };
}

// 3b. Ask the course scanner to scan the folder
async function scan(codeDir) {
  const res = await fetch(`${SCANNER_URL}/scan/directory`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ dirpath: codeDir }),
  });
  if (!res.ok) throw new Error(`Scanner returned ${res.status}: ${await res.text()}`);
  return res.json();
}

async function processJob(job) {
  const started = Date.now();
  console.log("Job started", { jobId: job.jobId, repo: job.repo, pr: job.pr, commitSha: job.commitSha });
  const { workDir, codeDir } = await downloadCode(job.repo, job.commitSha);
  try {
    const result = await scan(codeDir);
    // /scan/directory returns { summary, results: { "<file path>": [findings...] } }
    const vulns = Object.values(result.results || {}).flat();
    const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    vulns.forEach((v) => { if (counts[v.severity] !== undefined) counts[v.severity]++; });
    console.log("Job finished", {
      jobId: job.jobId, repo: job.repo, pr: job.pr, commitSha: job.commitSha,
      filesScanned: result.summary?.filesScanned, counts, total: vulns.length, durationMs: Date.now() - started,
    });
    // Decision (for now: any HIGH blocks; thresholds from .security-gate.yml come next)
    const state = counts.HIGH > 0 ? "failure" : "success";
    const description = `${counts.HIGH} HIGH, ${counts.MEDIUM} MEDIUM, ${counts.LOW} LOW` +
      (state === "failure" ? " - merge blocked" : " - passed");
    await setStatus(job.repo, job.commitSha, state, description);
    console.log("Status set", { pr: job.pr, state, description });

    // PR comment (a failure here must not undo the status or retry the scan)
    try {
      const body = buildComment(job, {
        state, counts, vulns, filesScanned: result.summary?.filesScanned,
        durationMs: Date.now() - started, codeDir,
      });
      const action = await upsertComment(job.repo, job.pr, body);
      console.log("PR comment " + action, { pr: job.pr });
    } catch (err) {
      console.warn("Could not post PR comment", { error: err.message });
    }

    // Short preview of findings (file paths made relative to the repo)
    vulns.slice(0, 10).forEach((v) =>
      console.log(`  ${v.severity}  ${v.id}  ${String(v.file).replace(codeDir + "/", "")}:${v.line}`));
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}

// 4. Main loop: long-poll SQS, delete a job only after it succeeds
async function main() {
  if (!QUEUE_URL) throw new Error("QUEUE_URL is not set");
  await waitForScanner();
  console.log("Worker polling", QUEUE_URL);

  while (running) {
    const out = await sqs.send(new ReceiveMessageCommand({
      QueueUrl: QUEUE_URL, MaxNumberOfMessages: 1, WaitTimeSeconds: 20,
      AttributeNames: ["ApproximateReceiveCount"],
    }));
    for (const msg of out.Messages || []) {
      const attempt = Number(msg.Attributes?.ApproximateReceiveCount || 1);
      let job;
      try {
        job = JSON.parse(msg.Body);
        await processJob(job);
        await sqs.send(new DeleteMessageCommand({ QueueUrl: QUEUE_URL, ReceiptHandle: msg.ReceiptHandle }));
      } catch (err) {
        // Not deleted: SQS makes it visible again for a retry; after the last try it goes to the DLQ
        console.error("Job failed", { error: err.message, attempt, maxAttempts: MAX_ATTEMPTS, messageId: msg.MessageId });
        if (job && attempt >= MAX_ATTEMPTS) {
          // Last try: never leave the PR stuck on "pending"
          try {
            await setStatus(job.repo, job.commitSha, "error", "DoubleCheck could not complete the scan - push again to retry");
            console.log("Status set to error after final attempt", { pr: job.pr });
          } catch (e) {
            console.error("Could not set error status", { error: e.message });
          }
        }
      }
    }
  }
}

process.on("SIGTERM", () => { console.log("SIGTERM: finishing current job"); running = false; });

main().catch((err) => { console.error("Worker crashed:", err); process.exit(1); });
