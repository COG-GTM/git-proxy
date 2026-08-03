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
import express, { Express } from 'express';
import request from 'supertest';
import pushRouter from '../../../src/service/routes/push';
import repoRoutes from '../../../src/service/routes/repo';
import * as db from '../../../src/db';
import { Proxy } from '../../../src/proxy';
import { buildQuery } from '../../../src/service/routes/utils';
import { PushQuery, RepoQuery } from '../../../src/db/types';

describe('API query parameter validation', () => {
  let app: Express;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use('/push', pushRouter);
    app.use('/repo', repoRoutes({} as Proxy));

    vi.spyOn(db, 'getPushes').mockResolvedValue([]);
    vi.spyOn(db, 'getRepos').mockResolvedValue([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('buildQuery', () => {
    it('accepts allowed keys and coerces booleans', () => {
      const query = buildQuery<PushQuery>({ blocked: 'false', authorised: 'true' }, [
        'blocked',
        'authorised',
      ]);
      expect(query).toEqual({ blocked: false, authorised: true });
    });

    it('ignores pagination, operator, dotted, unknown and non-scalar parameters', () => {
      const query = buildQuery<RepoQuery>(
        {
          name: 'test-repo',
          limit: '10',
          skip: '5',
          $where: '1 === 1',
          'users.canPush': 'someone',
          unknown: 'value',
          url: ['a', 'b'],
          project: { $ne: '' },
        },
        ['name', 'url', 'project'],
      );
      expect(query).toEqual({ name: 'test-repo' });
    });
  });

  describe('GET /repo', () => {
    it('passes through legitimate filters', async () => {
      const res = await request(app).get('/repo?name=test-repo&url=https://example.com/a.git');

      expect(res.status).toBe(200);
      expect(db.getRepos).toHaveBeenCalledWith({
        name: 'test-repo',
        url: 'https://example.com/a.git',
      });
    });

    it('drops injected operators, dotted paths and unknown keys', async () => {
      const res = await request(app).get(
        '/repo?name=test-repo&$where=1%3D%3D1&users.canPush=someone&admin=true',
      );

      expect(res.status).toBe(200);
      expect(db.getRepos).toHaveBeenCalledWith({ name: 'test-repo' });
    });
  });

  describe('GET /push', () => {
    it('passes through legitimate filters and always forces type=push', async () => {
      const res = await request(app).get('/push?blocked=false&authorised=true');

      expect(res.status).toBe(200);
      expect(db.getPushes).toHaveBeenCalledWith({
        blocked: false,
        authorised: true,
        type: 'push',
      });
    });

    it('drops injected operators, dotted paths and unknown keys', async () => {
      const res = await request(app).get(
        '/push?blocked=false&$where=1%3D%3D1&commitData.message=x&type=pull',
      );

      expect(res.status).toBe(200);
      expect(db.getPushes).toHaveBeenCalledWith({ blocked: false, type: 'push' });
    });
  });
});
