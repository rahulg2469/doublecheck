// DoubleCheck - dead-letter queue handler Lambda
// Triggered by doublecheck-sast-jobs-dlq. A job lands here after failing 3 times,
// including when the worker crashed and couldn't clean up itself. For each dead job:
//   1. set the PR's commit status to "error" (so the PR never sits on "pending")
//   2. mark the job ERROR in doublecheck-jobs
//   3. email the team through SNS (developers hear through GitHub; the team hears here)

import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { DynamoDBClient, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";

const STATUS_CONTEXT = "DoubleCheck / SAST";
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
      "User-Agent": "doublecheck-dlq-handler",
    },
    body: JSON.stringify({ state, context: STATUS_CONTEXT, description: description.slice(0, 140) }),
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new Error(`GitHub status ${res.status}: ${(await res.text()).slice(0, 200)}`);
}

async function markJob(jobId, error) {
  const now = new Date().toISOString();
  await ddb.send(new UpdateItemCommand({
    TableName: process.env.JOBS_TABLE,
    Key: { jobId: { S: jobId } },
    // if_not_exists: a job with no PENDING row still gets createdAt, so it shows up in the ByStatus index
    UpdateExpression: "SET #s = :s, updatedAt = :u, #e = :e, createdAt = if_not_exists(createdAt, :u)",
    ExpressionAttributeNames: { "#s": "status", "#e": "error" },
    ExpressionAttributeValues: { ":s": { S: "ERROR" }, ":u": { S: now }, ":e": { S: error } },
  }));
}

async function alert(subject, lines) {
  await sns.send(new PublishCommand({
    TopicArn: process.env.ALERTS_TOPIC_ARN,
    Subject: subject.slice(0, 100),
    Message: lines.join("\n"),
  }));
}

export const handler = async (event) => {
  const failures = [];
  for (const record of event.Records || []) {
    let job;
    try {
      job = JSON.parse(record.body);
    } catch {
      // Unreadable message: alert with the raw body and let it go (never retry forever)
      console.error("Unreadable dead-letter message", { messageId: record.messageId });
      try {
        await alert("DoubleCheck: unreadable dead-letter message",
          ["A message in the SAST dead-letter queue could not be parsed.", "", record.body.slice(0, 2000)]);
      } catch (e) {
        failures.push({ itemIdentifier: record.messageId });
      }
      continue;
    }

    console.log("Dead job", { jobId: job.jobId, repo: job.repo, pr: job.pr, commitSha: job.commitSha });
    const problems = [];
    try {
      await setStatus(job.repo, job.commitSha, "error",
        "DoubleCheck could not complete the scan after 3 tries - push again to retry");
    } catch (err) {
      problems.push(`Could not set PR status: ${err.message}`);
    }
    try {
      await markJob(job.jobId, "Moved to the dead-letter queue after 3 failed attempts");
    } catch (err) {
      problems.push(`Could not update the job record: ${err.message}`);
    }

    try {
      await alert(`DoubleCheck: SAST scan failed for ${job.repo} PR #${job.pr}`, [
        "A SAST scan failed 3 times and was moved to the dead-letter queue.",
        "",
        `Repo:    ${job.repo}`,
        `PR:      #${job.pr}  https://github.com/${job.repo}/pull/${job.pr}`,
        `Commit:  ${job.commitSha}`,
        `Branch:  ${job.branch}`,
        `Job ID:  ${job.jobId}`,
        "",
        problems.length ? "Problems while handling it:\n" + problems.join("\n")
          : "The PR's check was set to \"error\" and the job marked ERROR.",
        "",
        "Check the worker logs: CloudWatch /doublecheck/sast-scanner",
      ]);
      console.log("Handled dead job", { jobId: job.jobId, problems });
    } catch (err) {
      // The alert is the point: report failure so SQS retries this message
      console.error("Could not send alert", { jobId: job.jobId, error: err.message });
      failures.push({ itemIdentifier: record.messageId });
    }
  }
  return { batchItemFailures: failures };
};
