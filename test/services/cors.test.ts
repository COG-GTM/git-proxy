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

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express, { Express } from 'express';
import cors from 'cors';
import request from 'supertest';
import { corsOptionsDelegate } from '../../src/service';

const buildApp = (): Express => {
  const app = express();
  app.use(cors(corsOptionsDelegate));
  app.get('/test', (_req, res) => {
    res.json({ message: 'ok' });
  });
  return app;
};

describe('CORS delegate (CWE-942 protection)', () => {
  const ORIGINAL = process.env.ALLOWED_ORIGINS;

  beforeEach(() => {
    delete process.env.ALLOWED_ORIGINS;
  });

  afterEach(() => {
    if (ORIGINAL === undefined) {
      delete process.env.ALLOWED_ORIGINS;
    } else {
      process.env.ALLOWED_ORIGINS = ORIGINAL;
    }
  });

  describe("wildcard mode (ALLOWED_ORIGINS='*')", () => {
    beforeEach(() => {
      process.env.ALLOWED_ORIGINS = '*';
    });

    it('returns a literal wildcard origin and NEVER allows credentials', async () => {
      const res = await request(buildApp()).get('/test').set('Origin', 'https://evil.example.com');

      expect(res.status).toBe(200);
      expect(res.headers['access-control-allow-origin']).toBe('*');
      // Must not reflect the arbitrary origin, and must not allow credentials.
      expect(res.headers['access-control-allow-origin']).not.toBe('https://evil.example.com');
      expect(res.headers['access-control-allow-credentials']).toBeUndefined();
    });

    it('does not send credentials on preflight requests', async () => {
      const res = await request(buildApp())
        .options('/test')
        .set('Origin', 'https://evil.example.com')
        .set('Access-Control-Request-Method', 'GET');

      expect(res.headers['access-control-allow-origin']).toBe('*');
      expect(res.headers['access-control-allow-credentials']).toBeUndefined();
    });
  });

  describe('allow-list mode (comma-separated origins)', () => {
    beforeEach(() => {
      process.env.ALLOWED_ORIGINS = 'https://app.example.com,https://admin.example.com';
    });

    it('echoes an allow-listed origin with credentials enabled', async () => {
      const res = await request(buildApp()).get('/test').set('Origin', 'https://app.example.com');

      expect(res.status).toBe(200);
      expect(res.headers['access-control-allow-origin']).toBe('https://app.example.com');
      expect(res.headers['access-control-allow-credentials']).toBe('true');
    });

    it('does not set CORS headers for a non-listed origin', async () => {
      const res = await request(buildApp()).get('/test').set('Origin', 'https://evil.example.com');

      expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('allows requests with no Origin header (same-origin/curl)', async () => {
      const res = await request(buildApp()).get('/test');
      expect(res.status).toBe(200);
    });
  });

  describe('same-origin mode (ALLOWED_ORIGINS unset)', () => {
    it('does not set an Access-Control-Allow-Origin header for cross-origin requests', async () => {
      const res = await request(buildApp()).get('/test').set('Origin', 'https://app.example.com');

      expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });
  });
});
