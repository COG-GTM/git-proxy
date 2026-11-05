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
import { buildQueryFilter } from '../../../src/service/routes/utils';
import { PushQuery, RepoQuery } from '../../../src/db/types';

describe('list endpoint query filters', () => {
  let app: Express;

  beforeEach(() => {
    app = express();
    app.use('/push', pushRouter);
    app.use('/repo', repoRoutes({} as Proxy));

    vi.spyOn(db, 'getPushes').mockResolvedValue([]);
    vi.spyOn(db, 'getRepos').mockResolvedValue([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('buildQueryFilter', () => {
    it('keeps allowlisted keys and coerces booleans', () => {
      const filter = buildQueryFilter<PushQuery>(
        { blocked: 'true', canceled: 'false', repo: 'r' },
        ['blocked', 'canceled', 'repo'],
      );
      expect(filter).toEqual({ blocked: true, canceled: false, repo: 'r' });
    });

    it('drops operator, dotted, unknown, pagination and non-string values', () => {
      const filter = buildQueryFilter<RepoQuery>(
        {
          name: 'repo-a',
          $where: 'while(true){}',
          'users.canPush': 'mallory',
          admin: 'true',
          limit: '10',
          skip: '5',
          url: ['a', 'b'],
          project: { $ne: '' },
        },
        ['name', 'url', 'project'],
      );
      expect(filter).toEqual({ name: 'repo-a' });
    });
  });

  describe('GET /push', () => {
    it('forwards allowlisted filters and forces type=push', async () => {
      const res = await request(app).get('/push?blocked=true&authorised=false&branch=main');

      expect(res.status).toBe(200);
      expect(db.getPushes).toHaveBeenCalledWith({
        blocked: true,
        authorised: false,
        branch: 'main',
        type: 'push',
      });
    });

    it('does not forward $where, dotted paths or type overrides', async () => {
      const res = await request(app).get(
        '/push?$where=while(true)%7B%7D&blocked=true&commitData.message=x&type=pull&limit=5',
      );

      expect(res.status).toBe(200);
      expect(db.getPushes).toHaveBeenCalledWith({ blocked: true, type: 'push' });
    });
  });

  describe('GET /repo', () => {
    it('forwards allowlisted filters', async () => {
      const res = await request(app).get('/repo?name=repo-a&project=finos');

      expect(res.status).toBe(200);
      expect(db.getRepos).toHaveBeenCalledWith({ name: 'repo-a', project: 'finos' });
    });

    it('does not forward $where, dotted paths or unknown keys', async () => {
      const res = await request(app).get(
        '/repo?$where=while(true)%7B%7D&users.canPush=mallory&_id=x&name=repo-a',
      );

      expect(res.status).toBe(200);
      expect(db.getRepos).toHaveBeenCalledWith({ name: 'repo-a' });
    });
  });
});
