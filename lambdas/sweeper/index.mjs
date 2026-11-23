// DoubleCheck - timeout sweeper Lambda
// Runs every 5 minutes (EventBridge). Finds SAST jobs stuck in PENDING or RUNNING
// for more than STALE_MINUTES (default 10), e.g. because the worker is down,
// and closes them: PR status "error", job ERROR, one summary email to the team.

import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { DynamoDBClient, QueryCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";

const STATUS_CONTEXT = "DoubleCheck / SAST";
const STALE_MINUTES = Number(process.env.STALE_MINUTES || 10);
const sm = new SecretsManagerClient({});
const ddb = new DynamoDBClient({});
const sns = new SNSClient({});
let token;

async function getToken() {
  if (!token) {
    const out = await sm.send(new GetSecretValueCommand({ SecretId: process.env.TOKEN_SECRET_ID }));
    token = out.SecretString.trim();
  }
  return token;
}

async function setStatus(repo, sha, state, description) {
  const res = await fetch(`https://api.github.com/repos/${repo}/statuses/${sha}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${await getToken()}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "doublecheck-sweeper",
    },
    body: JSON.stringify({ state, context: STATUS_CONTEXT, description: description.slice(0, 140) }),
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new Error(`GitHub status ${res.status}: ${(await res.text()).slice(0, 200)}`);
}

// All jobs in a status created before the cutoff (GSI ByStatus: status + createdAt)
async function findStale(status, cutoff) {
  const items = [];
  let key;
  do {
    const out = await ddb.send(new QueryCommand({
      TableName: process.env.JOBS_TABLE, IndexName: "ByStatus",
      KeyConditionExpression: "#s = :s AND createdAt < :c",
      ExpressionAttributeNames: { "#s": "status" },
      ExpressionAttributeValues: { ":s": { S: status }, ":c": { S: cutoff } },
      ExclusiveStartKey: key,
    }));
    items.push(...(out.Items || []));
    key = out.LastEvaluatedKey;
  } while (key);
  return items;
}

export const handler = async () => {
  const cutoff = new Date(Date.now() - STALE_MINUTES * 60 * 1000).toISOString();
  const stale = [...await findStale("PENDING", cutoff), ...await findStale("RUNNING", cutoff)];
  const closed = [];

  for (const item of stale) {
    const job = {
      jobId: item.jobId.S, oldStatus: item.status.S, repo: item.repo?.S,
      pr: item.pr?.N, commitSha: item.commitSha?.S, createdAt: item.createdAt?.S,
    };
    // Only close it if it's STILL stuck right now (the worker may have just finished it)
    try {
      await ddb.send(new UpdateItemCommand({
        TableName: process.env.JOBS_TABLE, Key: { jobId: { S: job.jobId } },
        UpdateExpression: "SET #s = :err, updatedAt = :u, #e = :e",
        ConditionExpression: "#s = :old",
        ExpressionAttributeNames: { "#s": "status", "#e": "error" },
        ExpressionAttributeValues: {
          ":err": { S: "ERROR" }, ":old": { S: job.oldStatus }, ":u": { S: new Date().toISOString() },
          ":e": { S: `Timed out: still ${job.oldStatus} after ${STALE_MINUTES} minutes` },
        },
      }));
    } catch (err) {
      if (err.name === "ConditionalCheckFailedException") continue; // finished in the meantime
      throw err;
    }

    let statusNote = "PR check set to error";
    if (job.repo && job.commitSha) {
      try {
        await setStatus(job.repo, job.commitSha, "error", "DoubleCheck scan timed out - push again to retry");
      } catch (err) {
        statusNote = `could not set PR status: ${err.message}`;
      }
    }
    closed.push({ ...job, statusNote });
    console.log("Closed stuck job", job);
  }

  if (closed.length) {
    await sns.send(new PublishCommand({
      TopicArn: process.env.ALERTS_TOPIC_ARN,
      Subject: `DoubleCheck: ${closed.length} stuck SAST job(s) timed out`.slice(0, 100),
      Message: [
        `${closed.length} SAST job(s) were stuck for more than ${STALE_MINUTES} minutes and were closed.`,
        "Is the worker running? Check ECS cluster doublecheck and CloudWatch /doublecheck/sast-scanner.",
        "",
        ...closed.map((j) => `- ${j.repo} PR #${j.pr} (commit ${String(j.commitSha).slice(0, 7)}), was ${j.oldStatus} since ${j.createdAt}: ${j.statusNote}`),
      ].join("\n"),
    }));
  }
  console.log("Sweep done", { checked: stale.length, closed: closed.length, cutoff });
  return { checked: stale.length, closed: closed.length };
};
