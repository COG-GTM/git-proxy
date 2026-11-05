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
import { Request } from 'express';
import { Action } from '../../src/proxy/actions';

vi.mock('../../src/db', () => ({
  getUsers: vi.fn(),
  isUserPushAllowed: vi.fn(),
}));

vi.mock('axios', () => ({
  default: { get: vi.fn() },
}));

// import after mocking
import axios from 'axios';
import { getUsers } from '../../src/db';
import { exec } from '../../src/proxy/processors/push-action/resolvePusher';
import { exec as checkUserPushPermission } from '../../src/proxy/processors/push-action/checkUserPushPermission';
import { isUserPushAllowed } from '../../src/db';

const GITHUB_URL = 'https://github.com/finos/git-proxy.git';

const basicAuth = (username: string, password: string) =>
  `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;

describe('resolvePusher', () => {
  let action: Action;
  let req: Request;

  beforeEach(() => {
    action = new Action('1', 'push', 'POST', 1, GITHUB_URL);
    req = { headers: { authorization: basicAuth('anything', 'ghp_token') } } as Request;
    vi.mocked(axios.get).mockResolvedValue({ data: { login: 'alice-gh' } });
    vi.mocked(getUsers).mockResolvedValue([
      { username: 'alice', email: 'alice@test.com', gitAccount: 'Alice-GH' },
      { username: 'bob', email: 'bob@test.com', gitAccount: 'bob-gh' },
    ] as any);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('sets the authenticated pusher on the action for push plugins', async () => {
    action.user = 'bob';
    action.userEmail = 'bob@test.com';

    const result = await exec(req, action);

    expect(result.user).toBe('alice');
    expect(result.userEmail).toBe('alice@test.com');
    expect(result.steps[0].stepName).toBe('resolvePusher');
    expect(result.steps[0].error).toBe(false);
  });

  it('verifies the credentials once for both resolvePusher and checkUserPushPermission', async () => {
    vi.mocked(isUserPushAllowed).mockResolvedValue(true);

    await exec(req, action);
    vi.mocked(axios.get).mockRejectedValue(new Error('provider unavailable'));
    const result = await checkUserPushPermission(req, action);

    expect(axios.get).toHaveBeenCalledTimes(1);
    expect(isUserPushAllowed).toHaveBeenCalledWith(GITHUB_URL, 'alice');
    expect(result.steps[1].error).toBe(false);
  });

  it('leaves the identity unset without blocking when no single user matches', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: { login: 'mallory-gh' } });

    const result = await exec(req, action);

    expect(result.user).toBeUndefined();
    expect(result.userEmail).toBeUndefined();
    expect(result.steps[0].error).toBe(false);
  });

  it('leaves the identity unset without blocking when credentials are missing', async () => {
    req = { headers: {} } as Request;

    const result = await exec(req, action);

    expect(getUsers).not.toHaveBeenCalled();
    expect(result.user).toBeUndefined();
    expect(result.steps[0].error).toBe(false);
  });
});
