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

import { describe, it, beforeEach, expect, vi, type Mock, afterEach } from 'vitest';
import { ADProfile } from '../src/service/passport/types.js';
import ActiveDirectory from 'activedirectory2';

let ldapStub: { isUserInAdGroup: Mock };
let dbStub: { updateUser: Mock; findUser: Mock };
let passportStub: {
  use: Mock;
  serializeUser: Mock;
  deserializeUser: Mock;
};
let strategyCallback: (
  req: Request,
  profile: ADProfile,
  ad: ActiveDirectory,
  done: (err: unknown, user: unknown) => void,
) => void;

const newConfig = JSON.stringify({
  authentication: [
    {
      type: 'ActiveDirectory',
      enabled: true,
      adminGroup: 'test-admin-group',
      userGroup: 'test-user-group',
      domain: 'test.com',
      adConfig: {
        url: 'ldap://test-url',
        baseDN: 'dc=test,dc=com',
        searchBase: 'ou=users,dc=test,dc=com',
      },
    },
  ],
});

describe('ActiveDirectory auth method', () => {
  const mockReq = {} as Request;
  const mockAd = {} as ActiveDirectory;

  beforeEach(async () => {
    ldapStub = {
      isUserInAdGroup: vi.fn(),
    };

    dbStub = {
      updateUser: vi.fn(),
      findUser: vi.fn(),
    };

    passportStub = {
      use: vi.fn(),
      serializeUser: vi.fn(),
      deserializeUser: vi.fn(),
    };

    // mock fs for config
    vi.doMock('fs', (importOriginal) => {
      const actual = importOriginal();
      return {
        ...actual,
        existsSync: vi.fn().mockReturnValue(true),
        readFileSync: vi.fn().mockReturnValue(newConfig),
      };
    });

    // mock ldaphelper before importing activeDirectory
    vi.doMock('../../../src/service/passport/ldaphelper', () => ldapStub);
    vi.doMock('../../../src/db', () => dbStub);

    vi.doMock('passport-activedirectory', () => ({
      default: function (_: unknown, callback: (err: unknown, user: unknown) => void) {
        strategyCallback = callback;
        return {
          name: 'ActiveDirectory',
          authenticate: () => {},
        };
      },
    }));

    // First import config
    const config = await import('../../../src/config/index.js');
    config.initUserConfig();
    vi.doMock('../../../src/config', () => config);

    // then configure activeDirectory
    const { configure } = await import('../../../src/service/passport/activeDirectory.js');
    await configure(passportStub as any);
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
  });

  it('should authenticate a valid user and mark them as admin', async () => {
    const mockProfile = {
      _json: {
        sAMAccountName: 'test-user',
        mail: 'test@test.com',
        userPrincipalName: 'test@test.com',
        title: 'Test User',
      },
      displayName: 'Test User',
    };

    ldapStub.isUserInAdGroup
      .mockResolvedValueOnce(true) // adminGroup check
      .mockResolvedValueOnce(true); // userGroup check

    const done = vi.fn();

    await strategyCallback(mockReq, mockProfile, mockAd, done);

    expect(done).toHaveBeenCalledOnce();
    const [err, user] = done.mock.calls[0];
    expect(err).toBeNull();
    expect(user).toMatchObject({
      username: 'test-user',
      email: 'test@test.com',
      displayName: 'Test User',
      admin: true,
      title: 'Test User',
    });

    expect(dbStub.updateUser).toHaveBeenCalledOnce();
  });

  it('should fail if user is not in user group', async () => {
    const mockProfile = {
      _json: {
        sAMAccountName: 'bad-user',
        mail: 'bad@test.com',
        userPrincipalName: 'bad@test.com',
        title: 'Bad User',
      },
      displayName: 'Bad User',
    };

    ldapStub.isUserInAdGroup.mockResolvedValueOnce(false);

    const done = vi.fn();

    await strategyCallback(mockReq, mockProfile, mockAd, done);

    expect(done).toHaveBeenCalledOnce();
    const [err, user] = done.mock.calls[0];
    expect(err).toContain('not a member');
    expect(user).toBeNull();

    expect(dbStub.updateUser).not.toHaveBeenCalled();
  });

  it('should handle LDAP errors gracefully', async () => {
    const mockProfile = {
      _json: {
        sAMAccountName: 'error-user',
        mail: 'err@test.com',
        userPrincipalName: 'err@test.com',
        title: 'Whoops',
      },
      displayName: 'Error User',
    };

    ldapStub.isUserInAdGroup.mockRejectedValueOnce(new Error('LDAP error'));

    const done = vi.fn();

    await strategyCallback(mockReq, mockProfile, mockAd, done);

    expect(done).toHaveBeenCalledOnce();
    const [err, user] = done.mock.calls[0];
    expect(err).toContain('LDAP error');
    expect(user).toBeNull();
  });
  describe('session serialization', () => {
    const getSerializer = () => passportStub.serializeUser.mock.calls[0][0];
    const getDeserializer = () => passportStub.deserializeUser.mock.calls[0][0];

    it('should store only the username in the session', () => {
      const done = vi.fn();
      getSerializer()({ username: 'test-user', admin: true, email: 'test@test.com' }, done);
      expect(done).toHaveBeenCalledWith(null, 'test-user');
    });

    it('should reload the user from the database on every request', async () => {
      dbStub.findUser.mockResolvedValueOnce({ username: 'test-user', admin: false });
      const done = vi.fn();

      await getDeserializer()('test-user', done);

      expect(dbStub.findUser).toHaveBeenCalledWith('test-user');
      expect(done).toHaveBeenCalledWith(null, { username: 'test-user', admin: false });
    });

    it('should not trust the admin flag from a legacy session holding the full user object', async () => {
      dbStub.findUser.mockResolvedValueOnce({ username: 'test-user', admin: false });
      const done = vi.fn();

      await getDeserializer()({ username: 'test-user', admin: true }, done);

      expect(dbStub.findUser).toHaveBeenCalledWith('test-user');
      expect(done).toHaveBeenCalledWith(null, { username: 'test-user', admin: false });
    });

    it('should invalidate the session when the user no longer exists', async () => {
      dbStub.findUser.mockResolvedValueOnce(null);
      const done = vi.fn();

      await getDeserializer()('deleted-user', done);

      expect(done).toHaveBeenCalledWith(null, false);
    });

    it('should invalidate a session without a username', async () => {
      const done = vi.fn();

      await getDeserializer()({ admin: true }, done);

      expect(dbStub.findUser).not.toHaveBeenCalled();
      expect(done).toHaveBeenCalledWith(null, false);
    });

    it('should pass database errors to passport', async () => {
      const error = new Error('db down');
      dbStub.findUser.mockRejectedValueOnce(error);
      const done = vi.fn();

      await getDeserializer()('test-user', done);

      expect(done).toHaveBeenCalledWith(error, null);
    });
  });
});
