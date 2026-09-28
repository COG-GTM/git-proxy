/**
 * Copyright 2026 GitProxy Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Request } from 'express';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { Action } from '../../../src/proxy/actions';
import { exec as preReceive } from '../../../src/proxy/processors/push-action/preReceive';

const HOOK = path.resolve(__dirname, '../../../examples/gitlab/hooks/pre-receive.sh');
const ZERO = '0'.repeat(40);
const PUSHER = 'dev@acme.example';

type HookResult = { status: number | null; output: string };

// Pre-receive hooks execute Unix shell scripts, which is not supported on Windows
describe.skipIf(process.platform === 'win32')('GitLab example pre-receive hook', () => {
  let repo: string;
  let base: string;

  const git = (...args: string[]) => {
    const result = spawnSync('git', args, {
      cwd: repo,
      encoding: 'utf-8',
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: 'Dev',
        GIT_AUTHOR_EMAIL: PUSHER,
        GIT_COMMITTER_NAME: 'Dev',
        GIT_COMMITTER_EMAIL: process.env.TEST_COMMITTER_EMAIL ?? PUSHER,
      },
    });
    if (result.status !== 0) {
      throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
    }
    return result.stdout.trim();
  };

  const write = (file: string, content: string | Buffer) => {
    const full = path.join(repo, file);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  };

  const commitFiles = (files: Record<string, string | Buffer>, committerEmail = PUSHER) => {
    for (const [file, content] of Object.entries(files)) {
      write(file, content);
    }
    git('add', '-A');
    process.env.TEST_COMMITTER_EMAIL = committerEmail;
    try {
      git('commit', '-q', '-m', 'PAY-1: change');
    } finally {
      delete process.env.TEST_COMMITTER_EMAIL;
    }
    return git('rev-parse', 'HEAD');
  };

  const runHook = (
    oldRev: string,
    newRev: string,
    env: Record<string, string> = {},
  ): HookResult => {
    const result = spawnSync(HOOK, [], {
      cwd: repo,
      input: `${oldRev} ${newRev} refs/heads/feature/PAY-1\n`,
      encoding: 'utf-8',
      env: { ...process.env, ...env },
    });
    return { status: result.status, output: `${result.stdout}${result.stderr}` };
  };

  beforeEach(() => {
    repo = fs.mkdtempSync(path.join(os.tmpdir(), 'gitlab-hook-'));
    git('init', '-q', '-b', 'main');
    base = commitFiles({ 'README.md': '# service\n', 'src/app.js': 'console.log(1);\n' });
  });

  afterEach(() => {
    fs.rmSync(repo, { recursive: true, force: true });
  });

  it('auto-approves documentation-only changes (exit 0)', () => {
    const head = commitFiles({ 'docs/guide/intro.txt': 'hello\n', 'CHANGELOG.md': '## 1.0\n' });
    const result = runHook(base, head);
    expect(result.status).toBe(0);
    expect(result.output).toContain('documentation-only');
  });

  it('requires manual review for source changes (exit 2)', () => {
    const head = commitFiles({ 'src/app.js': 'console.log(2);\n', 'README.md': '# svc\n' });
    const result = runHook(base, head);
    expect(result.status).toBe(2);
    expect(result.output).toContain('src/app.js');
  });

  it('rejects files larger than the size limit (exit 1)', () => {
    const head = commitFiles({ 'docs/big.md': Buffer.alloc(2048, 'a') });
    const result = runHook(base, head, { GITPROXY_HOOK_MAX_FILE_BYTES: '1024' });
    expect(result.status).toBe(1);
    expect(result.output).toContain('docs/big.md is 2048 bytes');
  });

  it('rejects files over 5 MiB with the default limit (exit 1)', () => {
    const head = commitFiles({ 'assets/dump.sql': Buffer.alloc(5 * 1024 * 1024 + 1, 'a') });
    expect(runHook(base, head).status).toBe(1);
  });

  it.each([['build/app.EXE'], ['lib/vendor.jar'], ['certs/client.p12']])(
    'rejects blocked binary extension %s (exit 1)',
    (file) => {
      const head = commitFiles({ [file]: 'binary' });
      const result = runHook(base, head);
      expect(result.status).toBe(1);
      expect(result.output).toContain('blocked file extension');
    },
  );

  it('checks every commit in the pushed range, not just the tip', () => {
    commitFiles({ 'tools/installer.msi': 'binary' });
    git('rm', '-q', 'tools/installer.msi');
    git('commit', '-q', '-m', 'PAY-1: remove installer');
    const head = git('rev-parse', 'HEAD');
    expect(runHook(base, head).status).toBe(1);
  });

  it.each([['.gitlab-ci.yml'], ['CODEOWNERS'], ['.gitlab/merge_request_templates/default.md']])(
    'rejects changes to sensitive path %s by non-allowlisted pushers (exit 1)',
    (file) => {
      const head = commitFiles({ [file]: 'changed\n' });
      const result = runHook(base, head);
      expect(result.status).toBe(1);
      expect(result.output).toContain(`${PUSHER} may not modify protected paths: ${file}`);
    },
  );

  it('sends allowlisted sensitive-path changes to manual review (exit 2)', () => {
    const head = commitFiles(
      { '.gitlab-ci.yml': 'stages: [test]\n' },
      'Platform.Lead@acme.example',
    );
    const result = runHook(base, head, {
      GITPROXY_SENSITIVE_PATH_ALLOWLIST: 'someone@acme.example, platform.lead@acme.example',
    });
    expect(result.status).toBe(2);
    expect(result.output).toContain('(allowlisted) modified protected paths: .gitlab-ci.yml');
  });

  it('handles a new branch (zero old commit) using the remote-tracking refs as base', () => {
    const upstream = fs.mkdtempSync(path.join(os.tmpdir(), 'gitlab-hook-upstream-'));
    try {
      spawnSync('git', ['clone', '-q', repo, upstream]);
      const clone = repo;
      repo = upstream;
      const head = commitFiles({ 'docs/new.md': 'new\n' });
      expect(runHook(ZERO, head).status).toBe(0);
      repo = clone;
    } finally {
      fs.rmSync(upstream, { recursive: true, force: true });
    }
  });

  it('falls back to manual review when stdin is empty or the commit is unknown (exit 2)', () => {
    const empty = spawnSync(HOOK, [], { cwd: repo, input: '', encoding: 'utf-8' });
    expect(empty.status).toBe(2);
    expect(runHook(base, 'f'.repeat(40)).status).toBe(2);
  });

  it('appends an audit line per decision when GITPROXY_HOOK_LOG is set', () => {
    const logFile = path.join(repo, '..', `${path.basename(repo)}-audit.log`);
    try {
      const head = commitFiles({ 'lib/tool.jar': 'binary' });
      expect(runHook(base, head, { GITPROXY_HOOK_LOG: logFile }).status).toBe(1);
      const audit = fs.readFileSync(logFile, 'utf-8');
      expect(audit).toContain(`refs/heads/feature/PAY-1@${head}`);
      expect(audit).toContain('REJECTED: lib/tool.jar has a blocked file extension');
    } finally {
      fs.rmSync(logFile, { force: true });
    }
  });

  describe('through the GitProxy preReceive processor', () => {
    const action = (commitTo: string) => {
      const a = new Action('1', 'push', 'POST', Date.now(), 'https://gitlab.com/acme/app.git');
      a.proxyGitPath = path.dirname(repo);
      a.repoName = path.basename(repo);
      a.commitFrom = base;
      a.commitTo = commitTo;
      a.branch = 'refs/heads/feature/PAY-1';
      return a;
    };

    it('maps exit 0 to auto-approval', async () => {
      const result = await preReceive({} as Request, action(commitFiles({ 'a.md': 'x' })), HOOK);
      expect(result.autoApproved).toBe(true);
      expect(result.error).toBe(false);
    });

    it('maps exit 1 to auto-rejection', async () => {
      const result = await preReceive({} as Request, action(commitFiles({ 'x.dll': 'x' })), HOOK);
      expect(result.autoRejected).toBe(true);
    });

    it('maps exit 2 to manual review', async () => {
      const result = await preReceive({} as Request, action(commitFiles({ 'a.ts': 'x' })), HOOK);
      expect(result.autoApproved).toBe(false);
      expect(result.autoRejected).toBe(false);
      expect(result.error).toBe(false);
    });
  });
});
