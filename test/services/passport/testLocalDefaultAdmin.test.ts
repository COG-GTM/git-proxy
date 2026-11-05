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

import bcrypt from 'bcryptjs';
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

let dbStub: { findUser: Mock; createUser: Mock };
let serverConfigStub: { GIT_PROXY_ADMIN_PASSWORD: string | undefined };

const loadLocal = async () => {
  vi.resetModules();
  vi.doMock('../../../src/db', () => dbStub);
  vi.doMock('../../../src/config/env', () => ({ serverConfig: serverConfigStub }));
  return import('../../../src/service/passport/local');
};

describe('local auth createDefaultAdmin', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    dbStub = { findUser: vi.fn().mockResolvedValue(null), createUser: vi.fn() };
    serverConfigStub = { GIT_PROXY_ADMIN_PASSWORD: undefined };
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('../../../src/db');
    vi.doUnmock('../../../src/config/env');
  });

  it('never seeds admin/admin or user/user on a fresh database', async () => {
    const local = await loadLocal();
    await local.createDefaultAdmin();

    expect(dbStub.createUser).toHaveBeenCalledTimes(1);
    const [username, password, , , isAdmin] = dbStub.createUser.mock.calls[0];
    expect(username).toBe('admin');
    expect(isAdmin).toBe(true);
    expect(password).not.toBe('admin');
    expect(password.length).toBeGreaterThanOrEqual(24);
    expect(dbStub.createUser.mock.calls.some((c) => c[0] === 'user')).toBe(false);
    expect(warnSpy.mock.calls.some((c) => String(c[0]).includes(password))).toBe(true);
  });

  it('generates a different password on each fresh bootstrap', async () => {
    const local = await loadLocal();
    await local.createDefaultAdmin();
    await local.createDefaultAdmin();
    const [first, second] = dbStub.createUser.mock.calls.map((c) => c[1]);
    expect(first).not.toBe(second);
  });

  it('uses GIT_PROXY_ADMIN_PASSWORD when set and does not log it', async () => {
    serverConfigStub.GIT_PROXY_ADMIN_PASSWORD = 'operator-chosen-secret';
    const local = await loadLocal();
    await local.createDefaultAdmin();

    expect(dbStub.createUser).toHaveBeenCalledWith(
      'admin',
      'operator-chosen-secret',
      'admin@place.com',
      'none',
      true,
    );
    expect(warnSpy.mock.calls.some((c) => String(c[0]).includes('operator-chosen-secret'))).toBe(
      false,
    );
  });

  it('does not recreate or reset an existing admin', async () => {
    dbStub.findUser.mockImplementation(async (username: string) =>
      username === 'admin' ? { username, password: await bcrypt.hash('rotated-pass', 4) } : null,
    );
    const local = await loadLocal();
    await local.createDefaultAdmin();

    expect(dbStub.createUser).not.toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('warns at startup while a legacy default password is still in use', async () => {
    const hashes: Record<string, string> = {
      admin: await bcrypt.hash('admin', 4),
      user: await bcrypt.hash('user', 4),
    };
    dbStub.findUser.mockImplementation(async (username: string) =>
      hashes[username] ? { username, password: hashes[username] } : null,
    );
    const local = await loadLocal();
    await local.createDefaultAdmin();

    const warnings = warnSpy.mock.calls.map((c) => String(c[0]));
    expect(warnings.some((w) => w.includes(`'admin' account still uses`))).toBe(true);
    expect(warnings.some((w) => w.includes(`'user' account still uses`))).toBe(true);
    expect(dbStub.createUser).not.toHaveBeenCalled();
  });
});
