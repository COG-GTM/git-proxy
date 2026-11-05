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

import { describe, it, beforeAll, afterAll, expect, vi } from 'vitest';
import { Request } from 'express';

vi.mock('axios', () => ({
  default: {
    get: vi.fn(async (_url: string, config: { headers: { Authorization: string } }) => ({
      data: { login: config.headers.Authorization.replace('Bearer token-for-', '') },
    })),
  },
}));
import * as processor from '../src/proxy/processors/push-action/checkUserPushPermission';
import { Action } from '../src/proxy/actions/Action';
import * as db from '../src/db';

const TEST_ORG = 'finos';
const TEST_REPO = 'user-push-perms-test.git';
const TEST_URL = 'https://github.com/finos/user-push-perms-test.git';
const TEST_USERNAME_1 = 'push-perms-test';
const TEST_EMAIL_1 = 'push-perms-test@test.com';
const TEST_USERNAME_2 = 'push-perms-test-2';
const TEST_EMAIL_2 = 'push-perms-test-2@test.com';

const reqAs = (gitAccount: string) =>
  ({
    headers: {
      authorization: `Basic ${Buffer.from(`ignored:token-for-${gitAccount}`).toString('base64')}`,
    },
  }) as Request;

describe('checkUserPushPermission', () => {
  let testRepo: Required<db.Repo> | null = null;

  beforeAll(async () => {
    testRepo = await db.createRepo({
      project: TEST_ORG,
      name: TEST_REPO,
      url: TEST_URL,
    });

    await db.createUser(TEST_USERNAME_1, 'abc', TEST_EMAIL_1, TEST_USERNAME_1, false);
    await db.addUserCanPush(testRepo._id, TEST_USERNAME_1);
    await db.createUser(TEST_USERNAME_2, 'abc', TEST_EMAIL_2, TEST_USERNAME_2, false);
  });

  afterAll(async () => {
    if (testRepo) await db.deleteRepo(testRepo._id);
    await db.deleteUser(TEST_USERNAME_1);
    await db.deleteUser(TEST_USERNAME_2);
  });

  it('allows pushes from an approved pusher', async () => {
    const action = new Action('1', 'type', 'method', 1, TEST_URL);
    const { error, user, userEmail } = await processor.exec(reqAs(TEST_USERNAME_1), action);
    expect(error).toBe(false);
    expect(user).toBe(TEST_USERNAME_1);
    expect(userEmail).toBe(TEST_EMAIL_1);
  });

  it('blocks pushes from an unapproved pusher', async () => {
    const action = new Action('1', 'type', 'method', 1, TEST_URL);
    const { error, errorMessage } = await processor.exec(reqAs(TEST_USERNAME_2), action);
    expect(error).toBe(true);
    expect(errorMessage).toContain('Your push has been blocked');
  });

  it('blocks pushes from an unknown pusher', async () => {
    const action = new Action('1', 'type', 'method', 1, TEST_URL);
    const { error, errorMessage } = await processor.exec(reqAs('unknown-account'), action);
    expect(error).toBe(true);
    expect(errorMessage).toContain('Your push has been blocked');
  });

  it('blocks an unapproved pusher who forges an approved committer email', async () => {
    const action = new Action('1', 'type', 'method', 1, TEST_URL);
    action.userEmail = TEST_EMAIL_1;
    const { error, errorMessage, user, userEmail } = await processor.exec(
      reqAs(TEST_USERNAME_2),
      action,
    );
    expect(error).toBe(true);
    expect(errorMessage).toContain(`${TEST_USERNAME_2} is not allowed to push`);
    expect(user).toBe(TEST_USERNAME_2);
    expect(userEmail).toBe(TEST_EMAIL_2);
  });
});
