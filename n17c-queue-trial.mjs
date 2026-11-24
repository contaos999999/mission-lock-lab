import { createPrivateKey, sign } from 'node:crypto';

const owner = 'contaos999999';
const repo = 'mission-lock-lab';
const project = `${owner}/${repo}`;
const route = `/repos/${project}`;
const pr = 1;
const head = 'f33aa1ebd388cad274099196bc8dd4aaeeb6a5be';
const author = 'edivanpablo99';
const reviewIds = new Map([['edivan5002', 6037036892], ['contaos9999', 6037083290]]);
const appId = 5900781;
const installationId = 185299765;
const repositoryId = 1469627758;
const bot = 'contaos-mission-lock-lab[bot]';
const authorization = 'mission-lock-lab/n17c-authorization';
const hold = 'mission-lock-lab/n17c-observation-hold';

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

async function api(path, token, method = 'GET', body) {
  const response = await fetch(`https://api.github.com${path}`, {
    method,
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'x-github-api-version': '2022-11-28',
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  requireCondition(response.ok, `${method} ${path}: HTTP ${response.status}`);
  return response.status === 204 ? undefined : response.json();
}

export function verifyReviews(reviews) {
  for (const [login, id] of reviewIds) {
    const recent = reviews.filter(review => review.user?.login?.toLowerCase() === login &&
      ['APPROVED', 'DISMISSED', 'CHANGES_REQUESTED'].includes(review.state)).at(-1);
    requireCondition(recent?.id === id && recent.state === 'APPROVED' &&
      recent.commit_id === head, `Expected live approval missing for ${login}`);
  }
}

export function verifyGroup(pull, build, commit, base) {
  const entry = pull?.mergeQueueEntry;
  const refName = build?.head_branch;
  requireCondition(pull?.number === pr && pull.state === 'OPEN' && pull.headRefOid === head &&
    pull.baseRefName === 'main' && entry?.id && entry.pullRequest?.number === pr &&
    ['AWAITING_CHECKS', 'MERGEABLE'].includes(entry.state) &&
    entry.baseCommit?.oid === base && entry.headCommit?.oid === build?.head_sha &&
    build?.event === 'merge_group' && build.status === 'completed' &&
    build.conclusion === 'success' &&
    /^gh-readonly-queue\/main\/pr-1-[0-9a-f]{7,40}$/.test(refName ?? '') &&
    commit?.sha === build.head_sha && commit.parents?.length === 2 &&
    commit.parents[0]?.sha === base && commit.parents[1]?.sha === head,
  'No authenticated single-PR live merge group for the pinned reviews and main');
  return { entryId: entry.id, sha: commit.sha, refName, runId: build.id };
}

function appJwt(key) {
  const encode = data => Buffer.from(JSON.stringify(data)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({
    iat: now - 60, exp: now + 480, iss: String(appId),
  })}`;
  const parsed = createPrivateKey(key.trim().replace(/\\r\\n|\\n|\\r/g, '\n').trim());
  requireCondition(parsed.asymmetricKeyType === 'rsa', 'An RSA private key is required');
  return `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), parsed).toString('base64url')}`;
}

export async function run(env) {
  const { LAB_OPERATION: operation, GITHUB_TOKEN: readToken, APP_PRIVATE_KEY: key,
    GITHUB_SHA: base } = env;
  requireCondition(env.GITHUB_REPOSITORY === project && env.GITHUB_REF === 'refs/heads/main' &&
    env.GITHUB_EVENT_NAME === 'workflow_dispatch' && env.GITHUB_ACTOR === owner &&
    env.GITHUB_TRIGGERING_ACTOR === owner && /^[0-9a-f]{40}$/.test(base ?? '') &&
    readToken && key && ['seed', 'admit', 'observe', 'revoke'].includes(operation),
  'Untrusted laboratory dispatch or missing credential');

  const read = path => api(path, readToken);
  async function verifyMain() {
    const current = await read(`${route}/git/ref/heads/main`);
    requireCondition(current.object?.sha === base, 'The lab base changed after dispatch');
  }
  async function verifyPull() {
    const pull = await read(`${route}/pulls/${pr}`);
    requireCondition(pull.state === 'open' && !pull.merged && pull.head?.sha === head &&
      pull.user?.login === author && pull.base?.ref === 'main' &&
      pull.base?.repo?.full_name === project && pull.changed_files === 1,
    'Unexpected pull request state or scope');
    const files = await read(`${route}/pulls/${pr}/files?per_page=2`);
    requireCondition(files.length === 1 && files[0].filename === 'README.md' &&
      files[0].additions === 5 && files[0].deletions === 0, 'Unexpected synthetic diff');
    const reviews = await read(`${route}/pulls/${pr}/reviews?per_page=100`);
    requireCondition(reviews.length < 100, 'Unexpected review pagination');
    verifyReviews(reviews);
  }
  async function verifyEnforcement() {
    const ruleset = await read(`${route}/rulesets/27959454`);
    const contexts = ruleset.rules?.find(rule => rule.type === 'required_status_checks')
      ?.parameters?.required_status_checks ?? [];
    requireCondition(ruleset.enforcement === 'active' &&
      [authorization, hold].every(context => contexts.some(
        status => status.context === context && status.integration_id === appId)),
    'Both lab contexts must be required from the dedicated GitHub App');
  }
  async function readQueueEntry() {
    const result = await api('/graphql', readToken, 'POST', {
      query: `query {
        repository(owner: "contaos999999", name: "mission-lock-lab") {
          pullRequest(number: 1) {
            number state headRefOid baseRefName
            mergeQueueEntry { id state baseCommit { oid } headCommit { oid } pullRequest { number } }
          }
        }
      }`,
    });
    requireCondition(!result.errors?.length, 'GitHub queue lookup failed');
    return result.data?.repository?.pullRequest;
  }
  async function readLiveGroup() {
    const [pull, runs] = await Promise.all([
      readQueueEntry(),
      read(`${route}/actions/workflows/queue-diagnostics.yml/runs?event=merge_group&per_page=30`),
    ]);
    const sha = pull?.mergeQueueEntry?.headCommit?.oid;
    requireCondition(/^[0-9a-f]{40}$/.test(sha ?? ''), 'No active merge-group SHA');
    const build = runs.workflow_runs?.find(run => run.head_sha === sha &&
      run.event === 'merge_group' && run.conclusion === 'success');
    requireCondition(build, 'No successful merge_group diagnostic for the active SHA');
    const commit = await read(`${route}/commits/${sha}`);
    const group = verifyGroup(pull, build, commit, base);
    const actualRef = await read(`${route}/git/ref/heads/${group.refName}`);
    requireCondition(actualRef?.object?.sha === group.sha, 'Queue group ref changed or was removed');
    return group;
  }

  await verifyMain();
  if (operation !== 'seed') {
    await verifyEnforcement();
    await verifyPull();
  }
  const jwt = appJwt(key);
  const installation = await api(`/app/installations/${installationId}`, jwt);
  requireCondition(installation.app_id === appId && installation.account?.login === owner &&
    installation.repository_selection === 'selected', 'Unexpected App installation');
  const { token } = await api(`/app/installations/${installationId}/access_tokens`, jwt, 'POST', {
    repository_ids: [repositoryId], permissions: { statuses: 'write' },
  });
  try {
    const scope = await api('/installation/repositories', token);
    requireCondition(scope.total_count === 1 && scope.repositories?.[0]?.id === repositoryId,
      'The App token is not isolated to the lab');
    async function statuses(sha) {
      return api(`${route}/commits/${sha}/statuses?per_page=100`, token);
    }
    async function latest(sha, context) {
      return (await statuses(sha)).find(status => status.context === context);
    }
    async function post(sha, context, state, description) {
      const root = `https://github.com/${project}/actions/runs/${env.GITHUB_RUN_ID}`;
      const created = await api(`${route}/statuses/${sha}`, token, 'POST', {
        context, state, description, target_url: root,
      });
      const current = await latest(sha, context);
      requireCondition(current?.id === created.id && current.creator?.login === bot &&
        current.state === state, 'App status failed provenance readback');
      console.log(JSON.stringify({ operation, sha, context, state, statusId: current.id, appId }));
    }
    if (operation === 'seed') {
      await post(base, hold, 'pending', 'N17(c) lab context registration');
      await post(base, authorization, 'pending', 'N17(c) lab context registration');
      return;
    }
    if (operation === 'admit') {
      await verifyMain();
      await verifyPull();
      await post(head, hold, 'success', 'N17(c) hold applies only to the merge group');
      await post(head, authorization, 'success', 'N17(c) lab admission authorized');
      return;
    }
    const admission = await latest(head, authorization);
    requireCondition(admission?.creator?.login === bot && admission.state === 'success',
      'No active lab admission from the dedicated App');
    const group = await readLiveGroup();
    if (operation === 'observe') {
      await post(group.sha, hold, 'pending', 'Hold the group for the controlled revocation observation');
    }
    await verifyMain();
    await verifyPull();
    const finalGroup = await readLiveGroup();
    requireCondition(group.entryId === finalGroup.entryId && group.sha === finalGroup.sha,
      'Merge group moved during validation');
    const groupHold = await latest(group.sha, hold);
    requireCondition(groupHold?.creator?.login === bot && groupHold.state === 'pending',
      'Group is not held for the isolated test');
    const previous = await latest(group.sha, authorization);
    if (operation === 'observe') {
      requireCondition(!previous || previous.state === 'pending', 'Group authorization already decided');
      await post(group.sha, authorization, 'success', 'N17(c) lab group authorization active');
    } else {
      requireCondition(previous?.creator?.login === bot && previous.state === 'success',
        'No active group authorization to revoke');
      await post(group.sha, authorization, 'failure', 'N17(c) lab group authorization revoked');
      await post(head, authorization, 'failure', 'N17(c) lab admission revoked');
      await verifyPull();
      await verifyMain();
    }
    console.log(JSON.stringify({ operation, group, base, pr, head,
      approvals: [...reviewIds.values()], observationHold: groupHold.id }));
  } finally {
    await api('/installation/token', token, 'DELETE');
  }
}

if (process.env.GITHUB_ACTIONS === 'true') await run(process.env);
