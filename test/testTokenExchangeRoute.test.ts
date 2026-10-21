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

import express, { Express, Request, Response } from 'express';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import * as config from '../src/config';
import * as db from '../src/db';
import { getRouter } from '../src/proxy/routes';

const { upstreamAuthorizationHeaders } = vi.hoisted(() => ({
  upstreamAuthorizationHeaders: [] as Array<string | undefined>,
}));

vi.mock('express-http-proxy', () => ({
  default: vi.fn(() => (req: Request, res: Response) => {
    upstreamAuthorizationHeaders.push(req.headers.authorization);
    res.status(200).send('upstream');
  }),
}));

vi.mock('../src/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/db')>()),
  getAllProxiedHosts: vi.fn().mockResolvedValue(['github.com']),
}));

const externalToken = 'external-route-token';
const internalToken = 'internal-route-pat';
const internalTokenEnv = 'TOKEN_EXCHANGE_ROUTE_INTERNAL_PAT';
const tokenHash = (token: string): string => createHash('sha256').update(token).digest('hex');

const basicHeader = (username: string, token: string): string =>
  `Basic ${Buffer.from(`${username}:${token}`).toString('base64')}`;

describe('token exchange proxy route', () => {
  let app: Express;
  let originalEnvironment: NodeJS.ProcessEnv;

  beforeEach(async () => {
    originalEnvironment = { ...process.env };
    upstreamAuthorizationHeaders.length = 0;
    vi.spyOn(db, 'getAllProxiedHosts').mockResolvedValue(['github.com']);
    app = express();
    app.use('/', await getRouter());
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.env = { ...originalEnvironment };
  });

  it('forwards an exchanged header to the upstream proxy middleware', async () => {
    process.env[internalTokenEnv] = internalToken;
    vi.spyOn(config, 'getTokenExchange').mockReturnValue({
      enabled: true,
      mappings: [
        {
          externalTokenSha256: tokenHash(externalToken),
          internalTokenEnv,
          internalUsername: 'internalUser',
        },
      ],
    });

    const response = await request(app)
      .get('/github.com/finos/git-proxy.git/info/refs?service=git-upload-pack')
      .set('authorization', basicHeader('externalUser', externalToken))
      .set('user-agent', 'git/2.0');

    expect(response.status).toBe(200);
    expect(upstreamAuthorizationHeaders).toEqual([basicHeader('internalUser', internalToken)]);
  });

  it('rejects unmapped credentials with a Git protocol ERR packet before proxying', async () => {
    vi.spyOn(config, 'getTokenExchange').mockReturnValue({
      enabled: true,
      mappings: [],
    });

    const response = await request(app)
      .get('/github.com/finos/git-proxy.git/info/refs?service=git-upload-pack')
      .set('authorization', basicHeader('externalUser', 'unmapped-route-token'))
      .set('user-agent', 'git/2.0');

    expect(response.status).toBe(200);
    expect(response.text).toContain(
      'ERR Token exchange failed: credential not recognised by GitProxy',
    );
    expect(upstreamAuthorizationHeaders).toEqual([]);
  });

  it('forwards the original header unchanged when token exchange is disabled', async () => {
    const authorization = basicHeader('externalUser', externalToken);
    vi.spyOn(config, 'getTokenExchange').mockReturnValue({
      enabled: false,
    });

    const response = await request(app)
      .get('/github.com/finos/git-proxy.git/info/refs?service=git-upload-pack')
      .set('authorization', authorization)
      .set('user-agent', 'git/2.0');

    expect(response.status).toBe(200);
    expect(upstreamAuthorizationHeaders).toEqual([authorization]);
  });
});
