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

import request from 'supertest';
import { describe, it, afterEach, expect, vi } from 'vitest';
import { Express } from 'express';

const LIMIT = 3;

const startServiceWithTrustProxy = async (trustProxy: boolean | number | string): Promise<any> => {
  vi.resetModules();
  vi.doMock('../src/config', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
      ...actual,
      getRateLimit: () => ({ windowMs: 60_000, limit: LIMIT }),
      getTrustProxy: () => trustProxy,
      getCSRFProtection: () => false,
    };
  });
  const { Service } = await import('../src/service');
  const { Proxy } = await import('../src/proxy');
  const app: Express = await Service.start(new Proxy());
  return { app, Service };
};

const hitWithRotatingForwardedFor = async (app: Express, count: number) => {
  const statuses: number[] = [];
  for (let i = 0; i < count; i++) {
    const res = await request(app)
      .get('/api/v1/healthcheck')
      .set('X-Forwarded-For', `203.0.113.${i + 1}`);
    statuses.push(res.status);
  }
  return statuses;
};

describe('trust proxy and rate limiting', () => {
  let service: any;

  afterEach(async () => {
    await service?.stop();
    service = undefined;
    vi.doUnmock('../src/config');
    vi.resetModules();
  });

  it('should not let a direct client bypass the rate limit by rotating X-Forwarded-For when trustProxy is false', async () => {
    const started = await startServiceWithTrustProxy(false);
    service = started.Service;

    const statuses = await hitWithRotatingForwardedFor(started.app, LIMIT + 2);

    expect(statuses.slice(0, LIMIT)).toEqual(Array(LIMIT).fill(200));
    expect(statuses.slice(LIMIT)).toEqual([429, 429]);
    expect(started.app.get('trust proxy')).toBe(false);
  });

  it('should key the rate limit on X-Forwarded-For when a trusted proxy hop is configured', async () => {
    const started = await startServiceWithTrustProxy(1);
    service = started.Service;

    const statuses = await hitWithRotatingForwardedFor(started.app, LIMIT + 2);

    expect(statuses).toEqual(Array(LIMIT + 2).fill(200));
    expect(started.app.get('trust proxy')).toBe(1);
  });
});
