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

import { PassportStatic } from 'passport';
import { describe, it, beforeEach, afterEach, expect, vi, type Mock } from 'vitest';

import {
  safelyExtractEmail,
  getUsername,
  handleUserAuthentication,
} from '../src/service/passport/oidc';

describe('OIDC auth method', () => {
  let dbStub: any;
  let passportStub: any;
  let configure: (passport: PassportStatic) => Promise<PassportStatic>;
  let discoveryStub: Mock;
  let fetchUserInfoStub: Mock;

  const newConfig = JSON.stringify({
    authentication: [
      {
        type: 'openidconnect',
        enabled: true,
        oidcConfig: {
          issuer: 'https://fake-issuer.com',
          clientID: 'test-client-id',
          clientSecret: 'test-client-secret',
          callbackURL: 'https://example.com/callback',
          scope: 'openid profile email',
        },
      },
    ],
  });

  beforeEach(async () => {
    dbStub = {
      findUserByOIDC: vi.fn(),
      createUser: vi.fn(),
    };

    passportStub = {
      use: vi.fn(),
      serializeUser: vi.fn(),
      deserializeUser: vi.fn(),
    };

    discoveryStub = vi.fn().mockResolvedValue({ some: 'config' });
    fetchUserInfoStub = vi.fn();

    const strategyCtorStub = function (_options: unknown, _verifyFn: unknown) {
      return {
        name: 'openidconnect',
        currentUrl: vi.fn().mockReturnValue({}),
      };
    };

    // First mock the dependencies
    vi.resetModules();
    vi.doMock('../src/config', async () => {
      const actual = await vi.importActual('../src/config');
      return {
        ...actual,
        initUserConfig: vi.fn(),
      };
    });
    vi.doMock('fs', async (importOriginal) => {
      const actual = await importOriginal<typeof import('fs')>();
      return {
        ...actual,
        existsSync: vi.fn().mockReturnValue(true),
        readFileSync: vi.fn().mockReturnValue(newConfig),
      };
    });
    vi.doMock('../../db', () => dbStub);
    vi.doMock('../../config', async () => {
      const actual = await vi.importActual('../src/config');
      return actual;
    });
    vi.doMock('openid-client', () => ({
      discovery: discoveryStub,
      fetchUserInfo: fetchUserInfoStub,
    }));
    vi.doMock('openid-client/passport', () => ({
      Strategy: strategyCtorStub,
    }));

    // then import fresh OIDC module with mocks applied
    const oidcModule = await import('../src/service/passport/oidc');
    configure = oidcModule.configure;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should configure passport with OIDC strategy', async () => {
    await configure(passportStub);

    expect(discoveryStub).toHaveBeenCalledOnce();
    expect(passportStub.use).toHaveBeenCalledOnce();
    expect(passportStub.serializeUser).toHaveBeenCalledOnce();
    expect(passportStub.deserializeUser).toHaveBeenCalledOnce();
  });

  it('should authenticate an existing user', async () => {
    dbStub.findUserByOIDC.mockResolvedValue({ id: 'user123', username: 'test-user' });

    const done = vi.fn();
    await handleUserAuthentication({ sub: 'user123', email: 'user123@test.com' }, done);

    expect(done).toHaveBeenCalledWith(null, expect.objectContaining({ username: 'user123' }));
  });

  it('should handle discovery errors', async () => {
    discoveryStub.mockRejectedValue(new Error('discovery failed'));

    await expect(configure(passportStub)).rejects.toThrow(/discovery failed/);
  });

  it('should fail if no email in new user profile', async () => {
    const done = vi.fn();
    await handleUserAuthentication({ sub: 'sub-no-email' }, done);

    const [err, user] = done.mock.calls[0];
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toMatch(/No email/);
    expect(user).toBeUndefined();
  });

  describe('safelyExtractEmail', () => {
    it('should extract email from profile', () => {
      const profile = { sub: 'sub-test', email: 'test@test.com' };
      const email = safelyExtractEmail(profile);
      expect(email).toBe('test@test.com');
    });

    it('should extract email from profile with emails array', () => {
      const profile = { sub: 'sub-test', emails: [{ value: 'test@test.com' }] };
      const email = safelyExtractEmail(profile);
      expect(email).toBe('test@test.com');
    });

    it('should return null if no email in profile', () => {
      const profile = { sub: 'sub-test', name: 'test' };
      const email = safelyExtractEmail(profile);
      expect(email).toBeNull();
    });
  });

  describe('getUsername', () => {
    it('should generate username from email', () => {
      const email = 'test@test.com';
      const username = getUsername(email);
      expect(username).toBe('test');
    });

    it('should return empty string if no email', () => {
      const email = '';
      const username = getUsername(email);
      expect(username).toBe('');
    });
  });
});

describe('OIDC user identity binding', () => {
  type StoredUser = {
    username: string;
    email: string;
    password: string | null;
    gitAccount: string;
    admin: boolean;
    oidcId?: string;
  };
  let users: StoredUser[];
  let oidc: typeof import('../src/service/passport/oidc');

  const login = async (userInfo: Record<string, unknown>) => {
    const done = vi.fn();
    await oidc.handleUserAuthentication(userInfo as any, done);
    return done.mock.calls[0] as [unknown, Partial<StoredUser> | undefined];
  };

  beforeEach(async () => {
    users = [];
    const fakeDb = {
      findUser: vi.fn(
        async (u: string) => users.find((x) => x.username === u.toLowerCase()) ?? null,
      ),
      findUserByEmail: vi.fn(
        async (e: string) => users.find((x) => x.email === e.toLowerCase()) ?? null,
      ),
      findUserByOIDC: vi.fn(async (id: string) => users.find((x) => x.oidcId === id) ?? null),
      createUser: vi.fn(
        async (
          username: string,
          _password: string,
          email: string,
          gitAccount: string,
          admin: boolean,
          oidcId: string,
        ) => {
          if (users.some((x) => x.username === username.toLowerCase())) {
            throw new Error(`user ${username} already exists`);
          }
          if (users.some((x) => x.email === email.toLowerCase())) {
            throw new Error(`A user with email ${email} already exists`);
          }
          users.push({
            username: username.toLowerCase(),
            email: email.toLowerCase(),
            password: oidcId ? null : 'hashed',
            gitAccount,
            admin,
            ...(oidcId ? { oidcId } : {}),
          });
        },
      ),
      updateUser: vi.fn(async (user: StoredUser) => {
        const existing = users.find((x) => x.username === user.username);
        if (existing) Object.assign(existing, user);
      }),
    };

    vi.resetModules();
    vi.doMock('../src/db', () => fakeDb);
    oidc = await import('../src/service/passport/oidc');
  });

  afterEach(() => {
    vi.doUnmock('../src/db');
  });

  it('persists the subject and resolves the same account on a repeat login', async () => {
    const [err1, first] = await login({ sub: 'sub-alice', email: 'alice@acme.example' });
    expect(err1).toBeNull();
    expect(first).toMatchObject({ username: 'alice', oidcId: 'sub-alice' });

    const [err2, second] = await login({ sub: 'sub-alice', email: 'alice@acme.example' });
    expect(err2).toBeNull();
    expect(second).toMatchObject({ username: 'alice', oidcId: 'sub-alice' });
    expect(users).toHaveLength(1);
  });

  it('gives a different identity with the same email local part a distinct username', async () => {
    await login({ sub: 'sub-alice', email: 'alice@acme.example' });

    const [err, other] = await login({ sub: 'sub-mallory', email: 'alice@partner.example' });
    expect(err).toBeNull();
    expect(other?.username).toMatch(/^alice-[0-9a-f]{8}$/);
    expect(other?.oidcId).toBe('sub-mallory');
    expect(users.find((u) => u.username === 'alice')?.oidcId).toBe('sub-alice');
  });

  it('does not let an OIDC identity take over a local account username', async () => {
    users.push({
      username: 'bob',
      email: 'bob@acme.example',
      password: 'hashed',
      gitAccount: 'bob',
      admin: true,
    });

    const [err, user] = await login({ sub: 'sub-bob2', email: 'bob@other.example' });
    expect(err).toBeNull();
    expect(user?.username).not.toBe('bob');
    expect(users.find((u) => u.username === 'bob')?.oidcId).toBeUndefined();
  });

  it('does not bind an OIDC identity to an existing local account by email', async () => {
    users.push({
      username: 'carol',
      email: 'carol@acme.example',
      password: 'hashed',
      gitAccount: 'carol',
      admin: false,
    });

    const [err, user] = await login({ sub: 'sub-carol', email: 'carol@acme.example' });
    expect((err as Error).message).toMatch(/already exists/);
    expect(user).toBeUndefined();
    expect(users.find((u) => u.username === 'carol')?.oidcId).toBeUndefined();
  });

  it('binds a legacy OIDC account (no stored subject) on exact email match', async () => {
    users.push({
      username: 'dave',
      email: 'dave@acme.example',
      password: null,
      gitAccount: 'Edit me',
      admin: false,
    });

    const [err, user] = await login({ sub: 'sub-dave', email: 'dave@acme.example' });
    expect(err).toBeNull();
    expect(user).toMatchObject({ username: 'dave', oidcId: 'sub-dave' });
    expect(users).toHaveLength(1);
  });

  it('rejects a new account when the provider marks the email unverified', async () => {
    const [err, user] = await login({
      sub: 'sub-eve',
      email: 'eve@acme.example',
      email_verified: false,
    });
    expect((err as Error).message).toMatch(/not verified/);
    expect(user).toBeUndefined();
    expect(users).toHaveLength(0);
  });

  it('rejects a profile without a subject', async () => {
    const [err] = await login({ email: 'nosub@acme.example' });
    expect((err as Error).message).toMatch(/No subject/);
    expect(users).toHaveLength(0);
  });
});
