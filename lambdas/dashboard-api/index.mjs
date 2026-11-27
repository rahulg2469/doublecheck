// DoubleCheck - dashboard API Lambda (docs: "Dashboard API Contract (v1)")
// Read-only JSON for the dashboard, behind the same HTTP API as the webhook:
//   GET /api/repos                      every repo + its latest SAST / pentest result
//   GET /api/scans?repo=&days=&scanType=&limit=&cursor=   a repo's recent scans, newest first
//   GET /api/trends?repo=&weeks=&scanType=                weekly numbers, ready to chart
// Data: doublecheck-scans (repo + scanAt), written by the SAST worker (and later the pentest worker).

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand, ScanCommand } from "@aws-sdk/lib-dynamodb";

const TABLE = process.env.SCANS_TABLE || "doublecheck-scans";
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const SEVERITIES = ["HIGH", "MEDIUM", "LOW"];
const DAY = 24 * 3600 * 1000;

// ---------- helpers ----------
const json = (statusCode, body) => ({
  statusCode,
  headers: { "content-type": "application/json", "cache-control": "no-store" },
  body: JSON.stringify(body),
});
class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
const bad = (message) => new ApiError(400, "bad_request", message);

function intParam(q, name, def, min, max) {
  if (q[name] === undefined || q[name] === "") return def;
  const n = Number(q[name]);
  if (!Number.isInteger(n) || n < min || n > max) throw bad(`${name} must be a whole number from ${min} to ${max}`);
  return n;
}
function repoParam(q) {
  const repo = q.repo;
  if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo)) throw bad("repo is required (owner/name)");
  return repo;
}
function scanTypeParam(q, def) {
  const t = q.scanType || def;
  if (t !== undefined && t !== "sast" && t !== "pentest") throw bad("scanType must be sast or pentest");
  return t;
}
const zeroCounts = () => ({ HIGH: 0, MEDIUM: 0, LOW: 0 });
const outcomeKeys = (scanType) => (scanType === "pentest" ? ["alert", "warn", "clean"] : ["block", "warn", "pass"]);
const branchOf = (s) => s.branch || s.environment || "default";
const scanTime = (s) => String(s.scanAt).split("#")[0];

// Monday 00:00 UTC of the week containing t
function weekStart(t) {
  const d = new Date(t);
  const day = (d.getUTCDay() + 6) % 7; // Monday = 0
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - day));
}
const ymd = (d) => d.toISOString().slice(0, 10);

// One stored scan -> the shape in the contract
function toScan(s) {
  const gh = `https://github.com/${s.repo}`;
  return {
    jobId: s.jobId,
    scanType: s.scanType,
    scanAt: scanTime(s),
    pr: s.pr ?? null,
    prUrl: s.pr ? `${gh}/pull/${s.pr}` : null,
    commitSha: s.commitSha,
    commitUrl: s.commitSha ? `${gh}/commit/${s.commitSha}` : null,
    branch: s.branch ?? null,
    environment: s.environment ?? null,
    decision: s.decision,
    reason: s.reason ?? null,
    counts: { ...zeroCounts(), ...(s.counts || {}) },
    byType: s.byType || {},
    newCount: s.newCount ?? 0,
    fixedCount: s.fixedCount ?? 0,
    firstScan: Boolean(s.firstScan),
    ...(s.scanType === "pentest" ? { endpointsTested: s.endpointsTested ?? null } : { filesScanned: s.filesScanned ?? null }),
    durationMs: s.durationMs ?? null,
    configUsed: s.configUsed ? { block_on: s.configUsed.block_on, warn_on: s.configUsed.warn_on } : null,
    reportUrl: null, // filled in once GET /api/reports/{jobId} exists
  };
}

// All scans of a repo since `from` (ISO), newest first, every page
async function queryAll(repo, fromIso) {
  const items = [];
  let key;
  do {
    const out = await ddb.send(new QueryCommand({
      TableName: TABLE,
      KeyConditionExpression: "repo = :r AND scanAt >= :from",
      ExpressionAttributeValues: { ":r": repo, ":from": fromIso },
      ScanIndexForward: false,
      ExclusiveStartKey: key,
    }));
    items.push(...(out.Items || []));
    key = out.LastEvaluatedKey;
  } while (key);
  return items;
}

// ---------- GET /api/repos ----------
async function repos() {
  const items = [];
  let key;
  do {
    const out = await ddb.send(new ScanCommand({
      TableName: TABLE,
      ProjectionExpression: "repo, scanAt, scanType, jobId, pr, branch, environment, commitSha, decision, counts",
      ExclusiveStartKey: key,
    }));
    items.push(...(out.Items || []));
    key = out.LastEvaluatedKey;
  } while (key);

  const since30 = new Date(Date.now() - 30 * DAY).toISOString();
  const byRepo = new Map();
  for (const s of items) {
    const r = byRepo.get(s.repo) || { repo: s.repo, scansLast30Days: 0, latest: { sast: null, pentest: null }, newest: "" };
    if (scanTime(s) >= since30) r.scansLast30Days++;
    const t = s.scanType === "pentest" ? "pentest" : "sast";
    if (!r.latest[t] || s.scanAt > r.latest[t]._key) {
      r.latest[t] = {
        _key: s.scanAt, jobId: s.jobId, scanAt: scanTime(s), pr: s.pr ?? null,
        branch: s.branch ?? null, environment: s.environment ?? null, commitSha: s.commitSha,
        decision: s.decision, counts: { ...zeroCounts(), ...(s.counts || {}) },
      };
    }
    if (s.scanAt > r.newest) r.newest = s.scanAt;
    byRepo.set(s.repo, r);
  }
  const list = [...byRepo.values()]
    .sort((a, b) => (a.newest < b.newest ? 1 : -1))
    .map(({ newest, ...r }) => {
      for (const t of ["sast", "pentest"]) if (r.latest[t]) delete r.latest[t]._key;
      return { repo: r.repo, repoUrl: `https://github.com/${r.repo}`, scansLast30Days: r.scansLast30Days, latest: r.latest };
    });
  return { generatedAt: new Date().toISOString(), repos: list };
}

// ---------- GET /api/scans ----------
async function scans(q) {
  const repo = repoParam(q);
  const days = intParam(q, "days", 30, 1, 90);
  const limit = intParam(q, "limit", 50, 1, 200);
  const scanType = scanTypeParam(q);
  let startKey;
  if (q.cursor) {
    try { startKey = JSON.parse(Buffer.from(q.cursor, "base64url").toString("utf8")); }
    catch { throw bad("cursor is not valid"); }
    if (startKey.repo !== repo) throw bad("cursor belongs to another repo");
  }
  const params = {
    TableName: TABLE,
    KeyConditionExpression: "repo = :r AND scanAt >= :from",
    ExpressionAttributeValues: { ":r": repo, ":from": new Date(Date.now() - days * DAY).toISOString() },
    ScanIndexForward: false,
    Limit: limit,
    ExclusiveStartKey: startKey,
  };
  if (scanType) {
    params.FilterExpression = "scanType = :t";
    params.ExpressionAttributeValues[":t"] = scanType;
  }
  const out = await ddb.send(new QueryCommand(params));
  return {
    repo,
    days,
    scans: (out.Items || []).map(toScan),
    nextCursor: out.LastEvaluatedKey ? Buffer.from(JSON.stringify(out.LastEvaluatedKey)).toString("base64url") : null,
  };
}

// ---------- GET /api/trends ----------
// Latest scan per branch in a list of scans (input is newest first)
function latestPerBranch(list) {
  const seen = new Map();
  for (const s of list) if (!seen.has(branchOf(s))) seen.set(branchOf(s), s);
  return [...seen.values()];
}

async function trends(q) {
  const repo = repoParam(q);
  const weeks = intParam(q, "weeks", 8, 1, 26);
  const scanType = scanTypeParam(q, "sast");
  const keys = outcomeKeys(scanType);

  const firstWeek = weekStart(Date.now() - (weeks - 1) * 7 * DAY);
  const all = (await queryAll(repo, firstWeek.toISOString())).filter((s) => (s.scanType || "sast") === scanType);

  const series = [];
  for (let i = 0; i < weeks; i++) {
    const start = new Date(firstWeek.getTime() + i * 7 * DAY);
    const end = new Date(start.getTime() + 7 * DAY);
    const inWeek = all.filter((s) => scanTime(s) >= start.toISOString() && scanTime(s) < end.toISOString());

    // PR outcomes: each PR once, by its latest scan that week
    const prOutcomes = Object.fromEntries(keys.map((k) => [k, 0]));
    const prSeen = new Set();
    for (const s of inWeek) {
      if (s.pr == null || prSeen.has(s.pr)) continue;
      prSeen.add(s.pr);
      if (prOutcomes[s.decision] !== undefined) prOutcomes[s.decision]++;
    }
    // Open findings: latest scan of each branch active that week
    const openFindings = zeroCounts();
    for (const s of latestPerBranch(inWeek)) for (const sev of SEVERITIES) openFindings[sev] += Number(s.counts?.[sev] || 0);

    series.push({
      weekStart: ymd(start),
      scans: inWeek.length,
      prOutcomes,
      openFindings,
      newFindings: inWeek.reduce((n, s) => n + Number(s.newCount || 0), 0),
      fixedFindings: inWeek.reduce((n, s) => n + Number(s.fixedCount || 0), 0),
    });
  }

  // Totals over the window (PRs once, by their latest scan in the window)
  const totalOutcomes = Object.fromEntries(keys.map((k) => [k, 0]));
  const prSeen = new Set();
  for (const s of all) {
    if (s.pr == null || prSeen.has(s.pr)) continue;
    prSeen.add(s.pr);
    if (totalOutcomes[s.decision] !== undefined) totalOutcomes[s.decision]++;
  }
  const ruleCounts = {};
  for (const s of latestPerBranch(all)) {
    for (const [rule, n] of Object.entries(s.byType || {})) ruleCounts[rule] = (ruleCounts[rule] || 0) + Number(n);
  }
  const topRules = Object.entries(ruleCounts)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([ruleId, count]) => ({ ruleId, count }));

  return {
    repo, scanType, weeks,
    from: ymd(firstWeek),
    to: ymd(new Date(firstWeek.getTime() + (weeks * 7 - 1) * DAY)),
    series,
    totals: {
      scans: all.length,
      prOutcomes: totalOutcomes,
      newFindings: series.reduce((n, w) => n + w.newFindings, 0),
      fixedFindings: series.reduce((n, w) => n + w.fixedFindings, 0),
    },
    topRules,
  };
}

// ---------- router ----------
const ROUTES = { "/api/repos": repos, "/api/scans": scans, "/api/trends": trends };

export const handler = async (event) => {
  const method = event.requestContext?.http?.method || "GET";
  const route = ROUTES[event.rawPath];
  try {
    if (method !== "GET" || !route) throw new ApiError(404, "not_found", "No such endpoint");
    return json(200, await route(event.queryStringParameters || {}));
  } catch (err) {
    if (err instanceof ApiError) return json(err.status, { error: { code: err.code, message: err.message } });
    console.error("Dashboard API error", { path: event.rawPath, error: err.message, stack: err.stack });
    return json(500, { error: { code: "internal", message: "Something went wrong; see the logs" } });
  }
};
