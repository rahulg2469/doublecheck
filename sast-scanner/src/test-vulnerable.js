import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { exec, execSync } from 'child_process';

// HARDCODED_SECRET: intentionally vulnerable sample secrets
const password = 'admin1234';
const apiKey = 'ABCDEFGHIJKLMNOP';
const secretKey = '1234567890ABCDEF';
const accessToken = '1234567890ABCDEF1234567890ABCDEF';
const awsAccessKeyId = 'AKIA1234567890ABCDEF';
const awsSecretAccessKey = 'abcd1234abcd1234abcd1234abcd1234abcd1234';
const githubToken = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';

// HARDCODED_IP: intentionally vulnerable fixed infrastructure values
const dbHost = '192.168.1.10';
const internalService = '10.0.0.5:8080';

// INSECURE_RANDOM: intentionally vulnerable random generation
const weakToken = Math.random().toString(36).slice(2);
const weakSessionToken = Math.random() + '-session-token';

// WEAK_CRYPTO: intentionally vulnerable weak hashing algorithms
const md5Digest = crypto.createHash('md5').update(password).digest('hex');
const sha1Digest = crypto.createHash('sha1').update(apiKey).digest('hex');

// SECURITY_TODO: intentionally vulnerable security debt comments
// TODO: security fix authentication bypass before release
// HACK: temporary admin token check for demo

// SENSITIVE_DATA_LOG: intentionally vulnerable sensitive logging
console.log('password', password);
console.info('access token', accessToken);

// SQL_INJECTION: intentionally vulnerable dynamic SQL
function findUserByName(db, username) {
  return db.query("SELECT * FROM users WHERE username = '" + username + "'");
}

function deleteOrderById(db, orderId) {
  return db.query(`DELETE FROM orders WHERE id = ${orderId}`);
}

// NOSQL_INJECTION: intentionally vulnerable direct request usage in NoSQL queries
function findUsers(usersCollection, req) {
  return usersCollection.find(req.query);
}

function findOneUser(usersCollection, req) {
  return usersCollection.findOne(req.body);
}

function deleteUser(usersCollection, req) {
  return usersCollection.deleteOne(req.params);
}

// PATH_TRAVERSAL: intentionally vulnerable file path handling
function readRequestedFile(req) {
  return fs.readFileSync(req.query.file, 'utf8');
}

function writeRequestedFile(baseDir, req) {
  return fs.writeFileSync(baseDir + req.body.filename, req.body.content);
}

function resolveUserPath(req) {
  return path.join('/var/app/uploads', req.params.path);
}

const pathTraversalPayload = '../../etc/passwd';

// INSECURE_FUNCTION: intentionally vulnerable dynamic code/command execution
function runCommand(userInput) {
  return exec(userInput);
}

function runCommandSync(userInput) {
  return execSync(userInput);
}

function evaluateInput(userExpression) {
  return eval(userExpression);
}

function createDynamicFunction(userCode) {
  return new Function(userCode);
}

// XSS: intentionally vulnerable unsafe HTML rendering patterns
function renderProfile(req) {
  const htmlContainer = {
    innerHTML: '',
    outerHTML: '',
    insertAdjacentHTML: () => {}
  };

  htmlContainer.innerHTML = req.query.displayName;
  htmlContainer.outerHTML = req.body.profileHtml;

  const document = {
    write: () => {},
    writeln: () => {}
  };

  document.write(req.query.bio);
  document.writeln(req.query.signature);
  htmlContainer.insertAdjacentHTML('beforeend', req.body.extraHtml);
}

export {
  password,
  apiKey,
  secretKey,
  accessToken,
  awsAccessKeyId,
  awsSecretAccessKey,
  githubToken,
  dbHost,
  internalService,
  weakToken,
  weakSessionToken,
  md5Digest,
  sha1Digest,
  pathTraversalPayload,
  findUserByName,
  deleteOrderById,
  findUsers,
  findOneUser,
  deleteUser,
  readRequestedFile,
  writeRequestedFile,
  resolveUserPath,
  runCommand,
  runCommandSync,
  evaluateInput,
  createDynamicFunction,
  renderProfile
};
