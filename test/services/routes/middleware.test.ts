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

import { describe, it, expect, vi } from 'vitest';
import express, { Express, Request, Response, NextFunction } from 'express';
import request from 'supertest';
import { ensureAuthenticated } from '../../../src/service/routes/middleware';
import { jwtAuthHandler } from '../../../src/service/passport/jwtAuthHandler';
import usersRouter from '../../../src/service/routes/users';

describe('ensureAuthenticated', () => {
  const buildRes = () => {
    const res = {} as Response;
    res.status = vi.fn().mockReturnValue(res);
    res.send = vi.fn().mockReturnValue(res);
    return res;
  };

  it('calls next() for a passport session authenticated request', () => {
    const req = { isAuthenticated: () => true } as unknown as Request;
    const res = buildRes();
    const next = vi.fn() as unknown as NextFunction;

    ensureAuthenticated(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('calls next() for a request populated with req.user (e.g. JWT)', () => {
    const req = {
      isAuthenticated: () => false,
      user: { username: 'api-client' },
    } as unknown as Request;
    const res = buildRes();
    const next = vi.fn() as unknown as NextFunction;

    ensureAuthenticated(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('responds 401 when there is no session and no req.user', () => {
    const req = { isAuthenticated: () => false } as unknown as Request;
    const res = buildRes();
    const next = vi.fn() as unknown as NextFunction;

    ensureAuthenticated(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.send).toHaveBeenCalledWith({ message: 'Authentication required' });
  });
});

describe('GET /api/v1/user authentication', () => {
  let app: Express;

  // Mirror the mount in src/service/routes/index.ts (jwtAuthHandler then ensureAuthenticated).
  const buildApp = (): Express => {
    const a = express();
    a.use(express.json());
    a.use('/api/v1/user', jwtAuthHandler(), ensureAuthenticated, usersRouter);
    return a;
  };

  it('returns 401 when unauthenticated', async () => {
    app = buildApp();
    const res = await request(app).get('/api/v1/user');

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Authentication required');
  });
});
