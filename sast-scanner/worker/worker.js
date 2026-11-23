// DoubleCheck - SAST worker
// Pulls SAST jobs from SQS, downloads the PR's code at the exact commit,
// scans it with the course scanner (POST /scan/directory), sets the PR status
// and posts (or updates) one PR comment with masked findings.
// Block/warn thresholds come from .security-gate.yml on the PR's BASE branch,
// so a PR can't loosen its own rules. Every scan is saved: the full report to S3,
// a summary to DynamoDB (doublecheck-scans), job state to doublecheck-jobs,
// and fingerprints are compared with the previous scan for new vs. fixed.

import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from "@aws-sdk/client-sqs";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import yaml from "js-yaml";
import crypto from "node:crypto";
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

const exec = promisify(execFile);
const QUEUE_URL = process.env.QUEUE_URL;
const TOKEN_SECRET_ID = process.env.TOKEN_SECRET_ID || "doublecheck/github-token";
const STATUS_CONTEXT = "DoubleCheck / SAST";
const COMMENT_MARKER = "<!-- doublecheck:sast -->"; // finds our own comment again
const MAX_LISTED = 25; // findings shown in the comment
const MAX_ATTEMPTS = 3; // must match the queue's maxReceiveCount
const REPORTS_BUCKET = process.env.REPORTS_BUCKET;
const SCANS_TABLE = process.env.SCANS_TABLE || "doublecheck-scans";
const JOBS_TABLE = process.env.JOBS_TABLE || "doublecheck-jobs";
const SCANNER_URL = process.env.SCANNER_URL || "http://127.0.0.1:3000"; // IPv4: "localhost" can resolve to IPv6 and hang

const sqs = new SQSClient({});
const sm = new SecretsManagerClient({});
const s3 = new S3Client({});
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
  marshallOptions: { removeUndefinedValues: true },
});
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

// ---------- Thresholds (.security-gate.yml) ----------
const RANK = { LOW: 1, MEDIUM: 2, HIGH: 3 };
const DEFAULT_CONFIG = { block_on: "HIGH", warn_on: "MEDIUM" };

// Read the gate config from the PR's base branch (e.g. main), never from the PR itself
async function loadConfig(repo, baseBranch) {
  const res = await fetch(
    `https://api.github.com/repos/${repo}/contents/.security-gate.yml?ref=${encodeURIComponent(baseBranch)}`, {
      headers: {
        Authorization: `Bearer ${await getToken()}`,
        Accept: "application/vnd.github.raw",
        "User-Agent": "doublecheck-sast-worker",
      },
      signal: AbortSignal.timeout(5000),
    });
  if (res.status === 404) return { ...DEFAULT_CONFIG, source: "defaults (no .security-gate.yml)" };
  if (!res.ok) throw new Error(`Could not read .security-gate.yml: ${res.status}`);

  let parsed;
  try {
    parsed = yaml.load(await res.text(), { schema: yaml.FAILSAFE_SCHEMA }) || {};
  } catch {
    return { ...DEFAULT_CONFIG, source: "defaults (.security-gate.yml is not valid YAML)" };
  }
  const block = String(parsed.block_on || DEFAULT_CONFIG.block_on).toUpperCase();
  let warn = String(parsed.warn_on || DEFAULT_CONFIG.warn_on).toUpperCase();
  if (!RANK[block] || !RANK[warn]) {
    return { ...DEFAULT_CONFIG, source: "defaults (.security-gate.yml has invalid severities)" };
  }
  if (RANK[warn] > RANK[block]) warn = block; // warn above block makes no sense: treat as equal
  return { block_on: block, warn_on: warn, source: `.security-gate.yml on ${baseBranch}` };
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

function buildComment(job, { state, counts, vulns, hidden, config, filesScanned, durationMs, codeDir, delta }) {
  const short = job.commitSha.slice(0, 7);
  const head = state === "failure" ? "❌ **DoubleCheck SAST: merge blocked**"
    : vulns.length ? "⚠️ **DoubleCheck SAST: passed with warnings**"
    : "✅ **DoubleCheck SAST: no issues found**";
  const lines = [
    COMMENT_MARKER,
    head,
    "",
    `**${counts.HIGH} HIGH** · **${counts.MEDIUM} MEDIUM** · **${counts.LOW} LOW** in ${filesScanned ?? "?"} ` +
      `${filesScanned === 1 ? "file" : "files"} · commit \`${short}\` · ${(durationMs / 1000).toFixed(1)}s`,
  ];
  if (delta) {
    lines.push(delta.firstScan ? "First scan on this branch."
      : `Since the last scan on this branch: **${delta.newCount} new**, **${delta.fixedCount} fixed**.`);
  }
  lines.push("");
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
  if (hidden > 0) lines.push("", `${hidden} lower-severity finding(s) below \`warn_on: ${config.warn_on}\` are not shown.`);
  lines.push("", `<sub>Rules: block on ${config.block_on}, warn on ${config.warn_on} · from ${config.source}. ` +
    `Updated on every push; secrets are masked.</sub>`);
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

// ---------- Saving results ----------
// Fingerprint = rule + file + code snippet (no line number, so shifted code keeps its identity)
function fingerprint(v, relFile) {
  return crypto.createHash("sha256")
    .update(`sast|${v.id}|${relFile}|${String(v.evidence || "").trim()}`)
    .digest("hex").slice(0, 16);
}
const relPath = (codeDir, f) => (path.isAbsolute(String(f)) ? path.relative(codeDir, String(f)) : String(f));

// Newest earlier scan of the same repo + scan type + branch (GSI ByStream)
async function previousScan(stream) {
  const out = await ddb.send(new QueryCommand({
    TableName: SCANS_TABLE, IndexName: "ByStream",
    KeyConditionExpression: "#s = :s",
    ExpressionAttributeNames: { "#s": "stream" },
    ExpressionAttributeValues: { ":s": stream },
    ScanIndexForward: false, Limit: 1,
  }));
  const prev = out.Items?.[0];
  if (!prev) return null;
  if (!prev.fingerprints && prev.fingerprintsKey) {
    const obj = await s3.send(new GetObjectCommand({ Bucket: REPORTS_BUCKET, Key: prev.fingerprintsKey }));
    prev.fingerprints = JSON.parse(await obj.Body.transformToString());
  }
  return prev;
}

// Job state in doublecheck-jobs; a tracking failure must never fail the scan itself
async function updateJob(jobId, status, extra = {}) {
  if (!jobId) return;
  const fields = { status, updatedAt: new Date().toISOString(), ...extra };
  const names = {}, values = {}, sets = [];
  Object.entries(fields).forEach(([k, v], i) => {
    if (v === undefined) return;
    names[`#k${i}`] = k; values[`:v${i}`] = v; sets.push(`#k${i} = :v${i}`);
  });
  try {
    await ddb.send(new UpdateCommand({
      TableName: JOBS_TABLE, Key: { jobId },
      UpdateExpression: "SET " + sets.join(", "),
      ExpressionAttributeNames: names, ExpressionAttributeValues: values,
    }));
  } catch (err) {
    console.warn("Could not update job", { jobId, status, error: err.message });
  }
}

async function processJob(job, attempt = 1) {
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  console.log("Job started", { jobId: job.jobId, repo: job.repo, pr: job.pr, commitSha: job.commitSha, attempt });
  await updateJob(job.jobId, "RUNNING", { attempts: attempt, startedAt });
  const { workDir, codeDir } = await downloadCode(job.repo, job.commitSha);
  try {
    const result = await scan(codeDir);
    const filesScanned = result.summary?.filesScanned;
    // /scan/directory returns { summary, results: { "<file path>": [findings...] } }
    const vulns = Object.values(result.results || {}).flat();
    const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    const byType = {};
    vulns.forEach((v) => {
      if (counts[v.severity] !== undefined) counts[v.severity]++;
      byType[v.id] = (byType[v.id] || 0) + 1;
    });
    console.log("Job finished", {
      jobId: job.jobId, repo: job.repo, pr: job.pr, commitSha: job.commitSha,
      filesScanned, counts, total: vulns.length, durationMs: Date.now() - started,
    });

    // Normalized findings (contracts section 3), with masked evidence and fingerprints
    const findings = vulns.map((v) => {
      const rel = relPath(codeDir, v.file);
      return {
        fingerprint: fingerprint(v, rel), source: "sast", ruleId: v.id, ruleName: v.name,
        severity: v.severity, status: "FAIL", title: v.description,
        location: { file: rel, line: v.line, column: v.column },
        evidence: maskEvidence(v), recommendation: v.message || null,
      };
    });

    // New vs. fixed: compare with the previous scan of this branch
    const stream = `${job.repo}#sast#${job.branch}`;
    const prev = await previousScan(stream);
    const prevSet = new Set(prev?.fingerprints || []);
    const curSet = new Set(findings.map((f) => f.fingerprint));
    findings.forEach((f) => { f.isNew = !prevSet.has(f.fingerprint); });
    const delta = {
      firstScan: !prev,
      newCount: [...curSet].filter((x) => !prevSet.has(x)).length,
      fixedCount: prev ? [...prevSet].filter((x) => !curSet.has(x)).length : 0,
    };

    // Decision from the base branch's .security-gate.yml
    const config = await loadConfig(job.repo, job.baseBranch || "main");
    const blocking = vulns.filter((v) => (RANK[v.severity] || 0) >= RANK[config.block_on]);
    const shown = vulns.filter((v) => (RANK[v.severity] || 0) >= RANK[config.warn_on]);
    const warnings = shown.length - blocking.length;
    const state = blocking.length > 0 ? "failure" : "success";
    const decision = state === "failure" ? "block" : warnings > 0 ? "warn" : "pass";
    const totals = `${counts.HIGH} HIGH, ${counts.MEDIUM} MEDIUM, ${counts.LOW} LOW`;
    const description = state === "failure"
      ? `Merge blocked: ${blocking.length} at or above ${config.block_on} (${totals})`
      : warnings > 0 ? `Passed with ${warnings} warning(s) (${totals})` : `Passed (${totals})`;
    await setStatus(job.repo, job.commitSha, state, description);
    console.log("Status set", { pr: job.pr, state, description, config });

    // PR comment (a failure here must not undo the status or retry the scan)
    try {
      const body = buildComment(job, {
        state, counts, vulns: shown, hidden: vulns.length - shown.length, config,
        filesScanned, durationMs: Date.now() - started, codeDir, delta,
      });
      const action = await upsertComment(job.repo, job.pr, body);
      console.log("PR comment " + action, { pr: job.pr });
    } catch (err) {
      console.warn("Could not post PR comment", { error: err.message });
    }

    // Save: full report -> S3, summary -> doublecheck-scans (a failure here retries the job;
    // status and comment updates are safe to repeat)
    const finishedAt = new Date().toISOString();
    const durationMs = Date.now() - started;
    const [owner, name] = job.repo.split("/");
    const reportKey = `reports/${owner}/${name}/sast/${job.commitSha}/${job.jobId}.json`;
    const configUsed = { block_on: config.block_on, warn_on: config.warn_on, source: config.source };
    const report = {
      schemaVersion: 1, jobId: job.jobId, scanType: "sast", repo: job.repo, pr: job.pr,
      commitSha: job.commitSha, branch: job.branch, environment: null, startedAt, finishedAt, durationMs,
      decision, reason: description, configUsed, counts, byType, ...delta, findings, testErrors: [], filesScanned,
    };
    await s3.send(new PutObjectCommand({
      Bucket: REPORTS_BUCKET, Key: reportKey,
      Body: JSON.stringify(report, null, 2), ContentType: "application/json",
    }));

    const item = {
      repo: job.repo, scanAt: `${finishedAt}#${job.jobId}`, stream, schemaVersion: 1,
      jobId: job.jobId, scanType: "sast", pr: job.pr, commitSha: job.commitSha, branch: job.branch,
      decision, reason: description, counts, byType, configUsed,
      newCount: delta.newCount, fixedCount: delta.fixedCount, firstScan: delta.firstScan,
      durationMs, filesScanned, reportKey,
    };
    const fps = [...curSet];
    if (JSON.stringify(fps).length > 300000) {
      // Keep the item well under DynamoDB's 400 KB limit
      item.fingerprintsKey = reportKey.replace(/\.json$/, ".fingerprints.json");
      await s3.send(new PutObjectCommand({
        Bucket: REPORTS_BUCKET, Key: item.fingerprintsKey, Body: JSON.stringify(fps), ContentType: "application/json",
      }));
    } else {
      item.fingerprints = fps;
    }
    await ddb.send(new PutCommand({ TableName: SCANS_TABLE, Item: item }));
    await updateJob(job.jobId, "SUCCESS", { finishedAt, decision, reportKey });
    console.log("Results saved", { reportKey, newCount: delta.newCount, fixedCount: delta.fixedCount });

    // Short preview of findings (file paths made relative to the repo)
    findings.slice(0, 10).forEach((f) =>
      console.log(`  ${f.severity}  ${f.ruleId}  ${f.location.file}:${f.location.line}`));
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}

// 4. Main loop: long-poll SQS, delete a job only after it succeeds
async function main() {
  if (!QUEUE_URL) throw new Error("QUEUE_URL is not set");
  if (!REPORTS_BUCKET) throw new Error("REPORTS_BUCKET is not set");
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
        await processJob(job, attempt);
        await sqs.send(new DeleteMessageCommand({ QueueUrl: QUEUE_URL, ReceiptHandle: msg.ReceiptHandle }));
      } catch (err) {
        // Not deleted: SQS makes it visible again for a retry; after the last try it goes to the DLQ
        console.error("Job failed", { error: err.message, attempt, maxAttempts: MAX_ATTEMPTS, messageId: msg.MessageId });
        if (job) {
          await updateJob(job.jobId, attempt >= MAX_ATTEMPTS ? "ERROR" : "FAILED",
            { attempts: attempt, error: String(err.message).slice(0, 500) });
        }
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
