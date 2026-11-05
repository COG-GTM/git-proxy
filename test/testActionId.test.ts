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

import { describe, it, expect } from 'vitest';
import { Action } from '../src/proxy/actions';

const commitFrom = 'a'.repeat(40);
const commitTo = 'b'.repeat(40);

const makePush = (url: string, branch: string): Action => {
  const action = new Action('1', 'push', 'POST', 1, url);
  action.branch = branch;
  action.setCommit(commitFrom, commitTo);
  return action;
};

describe('Action push id', () => {
  it('is stable for the same repository, branch and commit range', () => {
    const first = makePush('https://github.com/acme/payments.git', 'refs/heads/main');
    const second = makePush('https://github.com/acme/payments.git', 'refs/heads/main');

    expect(first.id).toBe(second.id);
    expect(first.id.startsWith(`${commitFrom}__${commitTo}__`)).toBe(true);
  });

  it('differs when the same commit range is pushed to a different repository', () => {
    const sandbox = makePush('https://github.com/acme/sandbox.git', 'refs/heads/main');
    const payments = makePush('https://github.com/acme/payments.git', 'refs/heads/main');

    expect(sandbox.id).not.toBe(payments.id);
  });

  it('differs when the same commit range is pushed to a different branch', () => {
    const main = makePush('https://github.com/acme/payments.git', 'refs/heads/main');
    const feature = makePush('https://github.com/acme/payments.git', 'refs/heads/feature');

    expect(main.id).not.toBe(feature.id);
  });

  it('is recomputed when the branch is set after the commit range', () => {
    const action = new Action('1', 'push', 'POST', 1, 'https://github.com/acme/payments.git');
    action.setCommit(commitFrom, commitTo);
    const idWithoutBranch = action.id;
    action.setBranch('refs/heads/main');

    expect(action.id).not.toBe(idWithoutBranch);
    expect(action.id).toBe(makePush('https://github.com/acme/payments.git', 'refs/heads/main').id);
  });
});
