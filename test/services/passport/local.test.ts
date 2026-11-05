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
import bcrypt from 'bcryptjs';
import * as db from '../../../src/db';
import { createDefaultAdmin, ADMIN_PASSWORD_ENV_VAR } from '../../../src/service/passport/local';

describe('createDefaultAdmin', () => {
  const originalEnv = process.env[ADMIN_PASSWORD_ENV_VAR];
  let createUserSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    createUserSpy = vi.spyOn(db, 'createUser').mockResolvedValue(undefined);
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (originalEnv === undefined) {
      delete process.env[ADMIN_PASSWORD_ENV_VAR];
    } else {
      process.env[ADMIN_PASSWORD_ENV_VAR] = originalEnv;
    }
  });

  it('creates only the admin user with a random password when no env var is set', async () => {
    delete process.env[ADMIN_PASSWORD_ENV_VAR];
    vi.spyOn(db, 'findUser').mockResolvedValue(null);

    await createDefaultAdmin();

    expect(createUserSpy).toHaveBeenCalledTimes(1);
    const [username, password, , , isAdmin] = createUserSpy.mock.calls[0];
    expect(username).toBe('admin');
    expect(isAdmin).toBe(true);
    expect(password).not.toBe('admin');
    expect((password as string).length).toBeGreaterThanOrEqual(20);
    expect(logSpy.mock.calls.flat().join('\n')).toContain(password as string);
  });

  it('generates a different password each time', async () => {
    delete process.env[ADMIN_PASSWORD_ENV_VAR];
    vi.spyOn(db, 'findUser').mockResolvedValue(null);

    await createDefaultAdmin();
    await createDefaultAdmin();

    expect(createUserSpy.mock.calls[0][1]).not.toBe(createUserSpy.mock.calls[1][1]);
  });

  it('uses GIT_PROXY_ADMIN_PASSWORD when set and does not log it', async () => {
    process.env[ADMIN_PASSWORD_ENV_VAR] = 'from-env-secret';
    vi.spyOn(db, 'findUser').mockResolvedValue(null);

    await createDefaultAdmin();

    expect(createUserSpy).toHaveBeenCalledTimes(1);
    expect(createUserSpy.mock.calls[0][1]).toBe('from-env-secret');
    expect(logSpy.mock.calls.flat().join('\n')).not.toContain('from-env-secret');
  });

  it('never creates a "user" account', async () => {
    delete process.env[ADMIN_PASSWORD_ENV_VAR];
    vi.spyOn(db, 'findUser').mockResolvedValue(null);

    await createDefaultAdmin();

    expect(createUserSpy.mock.calls.map((c) => c[0])).not.toContain('user');
  });

  it('does not recreate or reset an existing admin', async () => {
    const hash = await bcrypt.hash('a-strong-password', 4);
    vi.spyOn(db, 'findUser').mockImplementation(async (username: string) =>
      username === 'admin'
        ? {
            username: 'admin',
            password: hash,
            email: 'admin@place.com',
            gitAccount: 'none',
            admin: true,
          }
        : null,
    );

    await createDefaultAdmin();

    expect(createUserSpy).not.toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('warns when legacy default credentials are still in use', async () => {
    const adminHash = await bcrypt.hash('admin', 4);
    const userHash = await bcrypt.hash('user', 4);
    vi.spyOn(db, 'findUser').mockImplementation(async (username: string) => {
      if (username === 'admin') {
        return { username, password: adminHash, email: 'a@x', gitAccount: 'none', admin: true };
      }
      if (username === 'user') {
        return { username, password: userHash, email: 'u@x', gitAccount: 'none', admin: false };
      }
      return null;
    });

    await createDefaultAdmin();

    const warnings = warnSpy.mock.calls.flat().join('\n');
    expect(warnings).toContain('"admin"');
    expect(warnings).toContain('"user"');
  });
});
