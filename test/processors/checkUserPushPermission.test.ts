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

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fc from 'fast-check';
import { Action, Step } from '../../src/proxy/actions';
import type { Mock } from 'vitest';
import { Request } from 'express';

vi.mock('../../src/db', () => ({
  getUsers: vi.fn(),
  isUserPushAllowed: vi.fn(),
}));

vi.mock('axios', () => ({
  default: { get: vi.fn() },
}));

// import after mocking
import axios from 'axios';
import { getUsers, isUserPushAllowed } from '../../src/db';
import { exec } from '../../src/proxy/processors/push-action/checkUserPushPermission';

const basicAuth = (username: string, password: string) =>
  `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;

const GITHUB_URL = 'https://github.com/finos/git-proxy.git';
const GENERIC_URL = 'https://git.example.com/finos/git-proxy.git';

describe('checkUserPushPermission', () => {
  let getUsersMock: Mock;
  let isUserPushAllowedMock: Mock;
  let axiosGetMock: Mock;

  beforeEach(() => {
    getUsersMock = vi.mocked(getUsers);
    isUserPushAllowedMock = vi.mocked(isUserPushAllowed);
    axiosGetMock = vi.mocked(axios.get);
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  describe('exec', () => {
    let action: Action;
    let req: Request;
    let stepLogSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      req = { headers: { authorization: basicAuth('anything', 'ghp_token') } } as Request;
      action = new Action('1234567890', 'push', 'POST', 1234567890, GITHUB_URL);
      stepLogSpy = vi.spyOn(Step.prototype, 'log');
      axiosGetMock.mockResolvedValue({ data: { login: 'git-user' } });
    });

    it('should allow push when the authenticated user has permission', async () => {
      getUsersMock.mockResolvedValue([
        { username: 'db-user', email: 'db-user@test.com', gitAccount: 'git-user' },
      ]);
      isUserPushAllowedMock.mockResolvedValue(true);

      const result = await exec(req, action);

      expect(axiosGetMock).toHaveBeenCalledWith(
        'https://api.github.com/user',
        expect.objectContaining({
          headers: expect.objectContaining({ Authorization: 'Bearer ghp_token' }),
        }),
      );
      expect(isUserPushAllowedMock).toHaveBeenCalledWith(GITHUB_URL, 'db-user');
      expect(result.steps).toHaveLength(1);
      expect(result.steps[0].error).toBe(false);
      expect(result.user).toBe('db-user');
      expect(result.userEmail).toBe('db-user@test.com');
      expect(stepLogSpy).toHaveBeenLastCalledWith(
        `User git-user is allowed to push on repo ${GITHUB_URL}`,
      );
    });

    it('should identify the pusher from credentials, ignoring commit committer metadata', async () => {
      // Mallory authenticates as herself but forges Bob's email on the committer line
      axiosGetMock.mockResolvedValue({ data: { login: 'mallory-gh' } });
      action.commitData = [
        {
          tree: 't',
          parent: 'p',
          author: 'Bob',
          committer: 'Bob',
          authorEmail: 'bob@acme.com',
          committerEmail: 'bob@acme.com',
          commitTimestamp: '0',
          message: 'm',
        },
      ];
      getUsersMock.mockResolvedValue([
        { username: 'bob', email: 'bob@acme.com', gitAccount: 'bob-gh' },
        { username: 'mallory', email: 'mallory@acme.com', gitAccount: 'Mallory-GH' },
      ]);
      isUserPushAllowedMock.mockResolvedValue(true);

      const result = await exec(req, action);

      expect(isUserPushAllowedMock).toHaveBeenCalledWith(GITHUB_URL, 'mallory');
      expect(result.user).toBe('mallory');
      expect(result.userEmail).toBe('mallory@acme.com');
    });

    it('should block a pusher whose account is not linked to a GitProxy user even if the committer email is', async () => {
      // Eve has upstream credentials but no GitProxy account
      axiosGetMock.mockResolvedValue({ data: { login: 'eve-gh' } });
      getUsersMock.mockResolvedValue([
        { username: 'bob', email: 'bob@acme.com', gitAccount: 'bob-gh' },
      ]);

      const result = await exec(req, action);

      expect(isUserPushAllowedMock).not.toHaveBeenCalled();
      expect(result.steps[0].error).toBe(true);
      expect(result.steps[0].errorMessage).toContain(
        `Your push has been blocked (eve-gh is not allowed to push on repo ${GITHUB_URL})`,
      );
      expect(result.userEmail).toBeUndefined();
    });

    it('should reject push when user has no permission', async () => {
      getUsersMock.mockResolvedValue([
        { username: 'db-user', email: 'db-user@test.com', gitAccount: 'git-user' },
      ]);
      isUserPushAllowedMock.mockResolvedValue(false);

      const result = await exec(req, action);

      expect(result.steps).toHaveLength(1);
      expect(result.steps[0].error).toBe(true);
      expect(stepLogSpy).toHaveBeenLastCalledWith(
        `Your push has been blocked (git-user is not allowed to push on repo ${GITHUB_URL})`,
      );
      expect(result.steps[0].errorMessage).toContain('Your push has been blocked');
    });

    it('should handle multiple users for git account by rejecting the push', async () => {
      getUsersMock.mockResolvedValue([
        { username: 'user1', email: 'user1@test.com', gitAccount: 'git-user' },
        { username: 'user2', email: 'user2@test.com', gitAccount: 'GIT-USER' },
      ]);

      const result = await exec(req, action);

      expect(result.steps).toHaveLength(1);
      expect(result.steps[0].error).toBe(true);
      expect(stepLogSpy).toHaveBeenLastCalledWith(
        'Your push has been blocked (there are multiple users with git account git-user)',
      );
    });

    it('should block the push when no Authorization header is provided', async () => {
      req = { headers: {} } as Request;

      const result = await exec(req, action);

      expect(axiosGetMock).not.toHaveBeenCalled();
      expect(getUsersMock).not.toHaveBeenCalled();
      expect(result.steps).toHaveLength(1);
      expect(result.steps[0].error).toBe(true);
      expect(result.steps[0].errorMessage).toContain(
        'Push blocked: Unable to authenticate the pusher',
      );
    });

    it('should block the push when the provider rejects the token', async () => {
      axiosGetMock.mockRejectedValue(new Error('Request failed with status code 401'));

      const result = await exec(req, action);

      expect(getUsersMock).not.toHaveBeenCalled();
      expect(result.steps[0].error).toBe(true);
      expect(result.steps[0].errorMessage).toContain(
        'Push blocked: Unable to authenticate the pusher',
      );
    });

    it('should use the Basic username for git servers that authenticate it', async () => {
      action = new Action('1', 'push', 'POST', 1, GENERIC_URL);
      req = { headers: { authorization: basicAuth('testuser', 'user123') } } as Request;
      getUsersMock.mockResolvedValue([
        { username: 'tester', email: 'tester@test.com', gitAccount: 'testuser' },
      ]);
      isUserPushAllowedMock.mockResolvedValue(true);

      const result = await exec(req, action);

      expect(axiosGetMock).not.toHaveBeenCalled();
      expect(isUserPushAllowedMock).toHaveBeenCalledWith(GENERIC_URL, 'tester');
      expect(result.steps[0].error).toBe(false);
      expect(result.userEmail).toBe('tester@test.com');
    });

    describe('fuzzing', () => {
      it('should not crash on arbitrary getUsers return values (fuzzing)', async () => {
        const userList = fc.sample(
          fc.array(
            fc.record({
              username: fc.string(),
              gitAccount: fc.string(),
            }),
            { maxLength: 5 },
          ),
          1,
        )[0];
        getUsersMock.mockResolvedValue(userList);
        isUserPushAllowedMock.mockResolvedValue(false);

        const result = await exec(req, action);

        expect(result.steps).toHaveLength(1);
        expect(result.steps[0].error).toBe(true);
      });
    });
  });
});
