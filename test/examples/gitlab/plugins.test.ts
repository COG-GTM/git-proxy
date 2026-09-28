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
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import path from 'path';

import { Action } from '../../../src/proxy/actions';
import { isCompatiblePlugin, PluginLoader } from '../../../src/plugin';
import {
  basicAuthUsername,
  findCommitsMissingTicket,
  globToRegExp,
  matchProtectedBranch,
  matchRestrictedGroup,
  parseList,
} from '../../../examples/gitlab/plugins/lib/policies.js';
import requireTicketReferencePlugin, {
  requireTicketReference,
} from '../../../examples/gitlab/plugins/require-ticket-reference.js';
import protectBranchesPlugin, {
  protectBranches,
} from '../../../examples/gitlab/plugins/protect-branches.js';
import restrictGroupClonesPlugin, {
  restrictGroupClones,
} from '../../../examples/gitlab/plugins/restrict-group-clones.js';

const PLUGIN_DIR = path.resolve(__dirname, '../../../examples/gitlab/plugins');
const GITLAB_URL = 'https://gitlab.com/acme-bank/platform/payments-api.git';
const SELF_HOSTED_URL = 'https://gitlab.example.internal/security/restricted/fraud-models.git';
const ENV_KEYS = [
  'GITPROXY_TICKET_PATTERN',
  'GITPROXY_PROTECTED_BRANCHES',
  'GITPROXY_RESTRICTED_GROUPS',
  'GITPROXY_RESTRICTED_GROUP_READERS',
];

const req = {} as Request;

const commit = (message: string) => ({
  message,
  authorEmail: 'dev@acme.example',
  committerEmail: 'dev@acme.example',
});

const pushAction = (branch: string, messages: string[], url = GITLAB_URL) => {
  const action = new Action('1', 'push', 'POST', Date.now(), url);
  action.branch = branch;
  action.commitData = messages.map(commit) as Action['commitData'];
  return action;
};

const basicAuth = (username: string) =>
  `Basic ${Buffer.from(`${username}:not-a-real-token`).toString('base64')}`;

describe('GitLab example plugins', () => {
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const key of ENV_KEYS) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of ENV_KEYS) {
      if (savedEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = savedEnv[key];
      }
    }
  });

  describe('plugin packaging', () => {
    it('exports GitProxy-compatible plugin instances', () => {
      expect(isCompatiblePlugin(requireTicketReferencePlugin, 'isGitProxyPushActionPlugin')).toBe(
        true,
      );
      expect(isCompatiblePlugin(protectBranchesPlugin, 'isGitProxyPushActionPlugin')).toBe(true);
      expect(isCompatiblePlugin(restrictGroupClonesPlugin, 'isGitProxyPullActionPlugin')).toBe(
        true,
      );
    });

    it('is loadable by the GitProxy PluginLoader from file paths', async () => {
      const loader = new PluginLoader([
        path.join(PLUGIN_DIR, 'require-ticket-reference.js'),
        path.join(PLUGIN_DIR, 'protect-branches.js'),
        path.join(PLUGIN_DIR, 'restrict-group-clones.js'),
      ]);
      await loader.load();
      expect(loader.pushPlugins).toHaveLength(2);
      expect(loader.pullPlugins).toHaveLength(1);
    });
  });

  describe('policy helpers', () => {
    it('parses comma and whitespace separated lists with a fallback', () => {
      expect(parseList('a, b  c,,d')).toEqual(['a', 'b', 'c', 'd']);
      expect(parseList('   ', ['x'])).toEqual(['x']);
      expect(parseList(undefined)).toEqual([]);
    });

    it('converts branch globs to anchored regular expressions', () => {
      expect(globToRegExp('release/*').test('release/1.2')).toBe(true);
      expect(globToRegExp('release/*').test('release/1.2/hotfix')).toBe(false);
      expect(globToRegExp('release/**').test('release/1.2/hotfix')).toBe(true);
      expect(globToRegExp('main').test('main-backup')).toBe(false);
      expect(globToRegExp('v1.?').test('v1.x')).toBe(true);
      expect(globToRegExp('v1.?').test('v10x')).toBe(false);
    });

    it('extracts the Basic auth username without exposing the token', () => {
      expect(basicAuthUsername(basicAuth('jdoe'))).toBe('jdoe');
      expect(basicAuthUsername('Bearer abc')).toBeNull();
      expect(basicAuthUsername(undefined)).toBeNull();
    });

    it('exempts merge commits from the ticket requirement', () => {
      const missing = findCommitsMissingTicket([
        commit("Merge branch 'feature/x' into 'main'"),
        commit('tidy up'),
      ]);
      expect(missing.map((c: { message: string }) => c.message)).toEqual(['tidy up']);
    });
  });

  describe('requireTicketReference', () => {
    it.each([
      ['PAY-123: add refund endpoint'],
      ['Fix rounding error\n\nCloses #42'],
      ['chore: bump deps (acme/platform#7)'],
      ['A1-9 allowed key with digits in project'],
    ])('allows "%s"', async (message) => {
      const result = await requireTicketReference(req, pushAction('feature/x', [message]));
      expect(result.error).toBe(false);
      expect(result.steps[0].stepName).toBe('requireTicketReference');
    });

    it.each([['add refund endpoint'], ['pay-123 lowercase key'], ['issue # 42'], ['PAY-: no id']])(
      'blocks "%s"',
      async (message) => {
        const result = await requireTicketReference(req, pushAction('feature/x', [message]));
        expect(result.error).toBe(true);
        expect(result.errorMessage).toContain('requireTicketReference');
        expect(result.errorMessage).toContain(message.split('\n')[0]);
      },
    );

    it('blocks the push when only one of several commits lacks a ticket', async () => {
      const result = await requireTicketReference(
        req,
        pushAction('feature/x', ['PAY-1: first', 'second without ticket', 'PAY-3: third']),
      );
      expect(result.error).toBe(true);
      expect(result.errorMessage).toContain('second without ticket');
      expect(result.errorMessage).not.toContain('PAY-1: first');
    });

    it('honours GITPROXY_TICKET_PATTERN', async () => {
      process.env.GITPROXY_TICKET_PATTERN = '^CHG\\d{7}\\b';
      const allowed = await requireTicketReference(
        req,
        pushAction('feature/x', ['CHG0012345 rotate certs']),
      );
      const blocked = await requireTicketReference(req, pushAction('feature/x', ['PAY-1: x']));
      expect(allowed.error).toBe(false);
      expect(blocked.error).toBe(true);
    });
  });

  describe('protectBranches', () => {
    it.each([['refs/heads/main'], ['refs/heads/master'], ['refs/heads/release/2026.09']])(
      'blocks direct pushes to %s',
      async (branch) => {
        const result = await protectBranches(req, pushAction(branch, ['PAY-1: x']));
        expect(result.error).toBe(true);
        expect(result.errorMessage).toContain('protectBranches');
        expect(result.errorMessage).toContain('merge request');
      },
    );

    it.each([
      ['refs/heads/feature/PAY-1-refunds'],
      ['refs/heads/maintenance'],
      ['refs/heads/release'],
      ['refs/heads/release/2026.09/hotfix'],
    ])('allows %s', async (branch) => {
      const result = await protectBranches(req, pushAction(branch, ['PAY-1: x']));
      expect(result.error).toBe(false);
    });

    it('honours GITPROXY_PROTECTED_BRANCHES', async () => {
      process.env.GITPROXY_PROTECTED_BRANCHES = 'develop, hotfix/**';
      expect(matchProtectedBranch('refs/heads/hotfix/a/b', parseList('develop, hotfix/**'))).toBe(
        'hotfix/**',
      );
      const develop = await protectBranches(req, pushAction('refs/heads/develop', ['PAY-1: x']));
      const main = await protectBranches(req, pushAction('refs/heads/main', ['PAY-1: x']));
      expect(develop.error).toBe(true);
      expect(main.error).toBe(false);
    });
  });

  describe('restrictGroupClones', () => {
    const pullAction = (url: string) => new Action('2', 'pull', 'GET', Date.now(), url);
    const pullReq = (username?: string) =>
      ({ headers: username ? { authorization: basicAuth(username) } : {} }) as Request;

    beforeEach(() => {
      process.env.GITPROXY_RESTRICTED_GROUPS =
        'gitlab.example.internal/security/restricted,gitlab.com/acme-bank/secret';
      process.env.GITPROXY_RESTRICTED_GROUP_READERS = 'alice, Bob';
    });

    it('matches only whole group path segments', () => {
      const groups = ['gitlab.example.internal/security/restricted'];
      expect(matchRestrictedGroup(SELF_HOSTED_URL, groups)).toBe(groups[0]);
      expect(
        matchRestrictedGroup(
          'https://gitlab.example.internal/security/restricted-ish/x.git',
          groups,
        ),
      ).toBeNull();
    });

    it('does nothing for repositories outside restricted groups', async () => {
      const result = await restrictGroupClones(pullReq(), pullAction(GITLAB_URL));
      expect(result.error).toBe(false);
      expect(result.steps[0].logs).toHaveLength(0);
    });

    it('allows and logs clones by allowlisted users (case-insensitive)', async () => {
      const result = await restrictGroupClones(pullReq('bob'), pullAction(SELF_HOSTED_URL));
      expect(result.error).toBe(false);
      expect(result.steps[0].logs.join('\n')).toContain('by bob');
    });

    it.each([['mallory'], [undefined]])('blocks clones by %s', async (username) => {
      const result = await restrictGroupClones(pullReq(username), pullAction(SELF_HOSTED_URL));
      expect(result.error).toBe(true);
      expect(result.errorMessage).toContain('restrictGroupClones');
    });
  });
});
