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
import type { Mock } from 'vitest';
import { Step } from '../../src/proxy/actions';

vi.mock('axios', () => ({
  default: { get: vi.fn() },
}));

import axios from 'axios';
import {
  getAuthenticatedGitAccount,
  parseBasicAuth,
} from '../../src/proxy/processors/pusherIdentity';

const basicAuth = (credentials: string) => `Basic ${Buffer.from(credentials).toString('base64')}`;

describe('pusherIdentity', () => {
  let axiosGetMock: Mock;
  let step: Step;

  beforeEach(() => {
    axiosGetMock = vi.mocked(axios.get);
    step = new Step('test');
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('parseBasicAuth', () => {
    it('parses username and password, keeping colons in the password', () => {
      expect(parseBasicAuth(basicAuth('user:pa:ss'))).toEqual({
        username: 'user',
        password: 'pa:ss',
      });
    });

    it.each([undefined, '', 'Bearer abc', 'Basic', basicAuth('no-separator'), basicAuth('user:')])(
      'returns null for %s',
      (header) => {
        expect(parseBasicAuth(header)).toBeNull();
      },
    );
  });

  describe('getAuthenticatedGitAccount', () => {
    it('resolves the GitHub token owner and ignores the Basic username', async () => {
      axiosGetMock.mockResolvedValue({ data: { login: 'real-owner' } });

      const account = await getAuthenticatedGitAccount(
        'https://github.com/org/repo.git',
        basicAuth('claimed-user:ghp_abc'),
        step,
      );

      expect(account).toBe('real-owner');
      expect(axiosGetMock).toHaveBeenCalledWith(
        'https://api.github.com/user',
        expect.objectContaining({
          headers: expect.objectContaining({ Authorization: 'Bearer ghp_abc' }),
        }),
      );
    });

    it('resolves the GitLab token owner from the same host', async () => {
      axiosGetMock.mockResolvedValue({ data: { username: 'gl-owner' } });

      const account = await getAuthenticatedGitAccount(
        'https://gitlab.example.com:8443/group/repo.git',
        basicAuth('oauth2:glpat-abc'),
        step,
      );

      expect(account).toBe('gl-owner');
      expect(axiosGetMock).toHaveBeenCalledWith(
        'https://gitlab.example.com:8443/api/v4/user',
        expect.objectContaining({
          headers: expect.objectContaining({ Authorization: 'Bearer glpat-abc' }),
        }),
      );
    });

    it('returns null when the provider lookup fails', async () => {
      axiosGetMock.mockRejectedValue(new Error('401'));

      const account = await getAuthenticatedGitAccount(
        'https://github.com/org/repo.git',
        basicAuth('user:bad'),
        step,
      );

      expect(account).toBeNull();
    });

    it('returns null when the provider returns no account', async () => {
      axiosGetMock.mockResolvedValue({ data: {} });

      const account = await getAuthenticatedGitAccount(
        'https://github.com/org/repo.git',
        basicAuth('user:token'),
        step,
      );

      expect(account).toBeNull();
    });

    it('does not trust the Basic username for other git servers', async () => {
      const account = await getAuthenticatedGitAccount(
        'https://git-server:8443/test-owner/test-repo.git',
        basicAuth('testuser:user123'),
        step,
      );

      expect(account).toBeNull();
      expect(axiosGetMock).not.toHaveBeenCalled();
    });

    it('returns null without credentials', async () => {
      const account = await getAuthenticatedGitAccount(
        'https://github.com/org/repo.git',
        undefined,
        step,
      );

      expect(account).toBeNull();
      expect(axiosGetMock).not.toHaveBeenCalled();
    });
  });
});
