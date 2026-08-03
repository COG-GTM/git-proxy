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

import { Express } from 'express';
import request from 'supertest';
import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

describe('Service CORS and session cookie', () => {
  let serviceModule: any;
  const originalAllowedOrigins = process.env.ALLOWED_ORIGINS;
  const originalNodeEnv = process.env.NODE_ENV;
  const originalUiPort = process.env.GIT_PROXY_UI_PORT;

  const startApp = async (): Promise<Express> => {
    serviceModule = await import('../src/service/index');
    return serviceModule.Service.start({});
  };

  beforeEach(() => {
    vi.resetModules();
    process.env.GIT_PROXY_UI_PORT = '0';

    vi.doMock('../src/config', async (importOriginal) => {
      const actual: any = await importOriginal();
      return {
        ...actual,
        getTLSEnabled: vi.fn().mockReturnValue(false),
        getRateLimit: vi.fn().mockReturnValue({ windowMs: 60 * 1000, max: 1000 }),
        getCookieSecret: vi.fn().mockReturnValue('test-secret'),
        getSessionMaxAgeHours: vi.fn().mockReturnValue(12),
        getCSRFProtection: vi.fn().mockReturnValue(false),
      };
    });

    vi.doMock('../src/db', async (importOriginal) => {
      const actual: any = await importOriginal();
      return { ...actual, getSessionStore: vi.fn().mockReturnValue(undefined) };
    });

    vi.doMock('../src/service/passport', () => ({
      configure: vi.fn().mockResolvedValue({
        initialize: vi.fn().mockReturnValue((_req: any, _res: any, next: any) => next()),
        session: vi.fn().mockReturnValue((_req: any, _res: any, next: any) => next()),
      }),
    }));

    vi.doMock('../src/service/routes', () => ({
      default: vi.fn().mockReturnValue((req: any, res: any, next: any) => {
        if (req.path === '/session-probe') {
          req.session.probe = 'value';
          res.status(200).send('ok');
          return;
        }
        next();
      }),
    }));
  });

  afterEach(async () => {
    try {
      await serviceModule?.Service.stop();
    } catch (err) {
      console.error('Error occurred when stopping the service: ', err);
    }
    vi.restoreAllMocks();
    process.env.ALLOWED_ORIGINS = originalAllowedOrigins;
    process.env.NODE_ENV = originalNodeEnv;
    if (originalAllowedOrigins === undefined) delete process.env.ALLOWED_ORIGINS;
    if (originalUiPort === undefined) {
      delete process.env.GIT_PROXY_UI_PORT;
    } else {
      process.env.GIT_PROXY_UI_PORT = originalUiPort;
    }
  });

  it('sets SameSite=Lax and HttpOnly on the session cookie', async () => {
    delete process.env.ALLOWED_ORIGINS;
    const app = await startApp();

    const res = await request(app).get('/session-probe');

    expect(res.status).toBe(200);
    const cookies = res.headers['set-cookie'] as unknown as string[];
    const sessionCookie = cookies.find((cookie) => cookie.startsWith('connect.sid='));
    expect(sessionCookie).toBeDefined();
    expect(sessionCookie).toMatch(/SameSite=Lax/i);
    expect(sessionCookie).toMatch(/HttpOnly/i);
  });

  it('allows credentials for an explicitly listed origin', async () => {
    process.env.ALLOWED_ORIGINS = 'https://gitproxy.example.com';
    const app = await startApp();

    const res = await request(app)
      .get('/session-probe')
      .set('Origin', 'https://gitproxy.example.com');

    expect(res.headers['access-control-allow-origin']).toBe('https://gitproxy.example.com');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });

  it('does not reflect an unlisted origin', async () => {
    process.env.ALLOWED_ORIGINS = 'https://gitproxy.example.com';
    const app = await startApp();

    const res = await request(app).get('/session-probe').set('Origin', 'https://evil.example.com');

    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('never combines a reflected origin with credentials for wildcard CORS in production', async () => {
    process.env.ALLOWED_ORIGINS = '*';
    process.env.NODE_ENV = 'production';
    const app = await startApp();

    const res = await request(app).get('/session-probe').set('Origin', 'https://evil.example.com');

    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(res.headers['access-control-allow-credentials']).toBeUndefined();
  });
});
