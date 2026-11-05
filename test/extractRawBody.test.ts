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

import { Request } from 'express';
import rawBody from 'raw-body';
import { PassThrough } from 'stream';
import { describe, it, beforeEach, expect, vi, Mock } from 'vitest';

// Tell Vitest to mock dependencies
vi.mock('raw-body', () => ({
  default: vi.fn().mockResolvedValue(Buffer.from('payload')),
}));

vi.mock('../src/proxy/chain', () => ({
  executeChain: vi.fn(),
}));

vi.mock('../src/db', () => ({
  getRepoByUrl: vi.fn(),
  writeAudit: vi.fn(),
  getAllProxiedHosts: vi.fn().mockResolvedValue([]),
}));

vi.mock('../src/config', () => ({
  getMaxPackSizeBytes: vi.fn().mockReturnValue(1024),
}));

// Now import the module-under-test, which will receive the mocked deps
import { extractRawBody, isPackPost } from '../src/proxy/routes';
import * as chain from '../src/proxy/chain';
import * as db from '../src/db';

describe('extractRawBody middleware', () => {
  let req: any;
  let res: any;
  let next: Mock;

  beforeEach(() => {
    (rawBody as Mock).mockClear();
    (chain.executeChain as Mock).mockClear();
    (db.getRepoByUrl as Mock).mockReset();
    (db.writeAudit as Mock).mockClear();
    (db.getRepoByUrl as Mock).mockImplementation(async (url: string) =>
      url === 'https://github.com/proj/foo.git' ? { url } : null,
    );

    req = new PassThrough();
    req.method = 'POST';
    req.url = '/proj/foo.git/git-upload-pack';
    req.originalUrl = req.url;
    req.headers = {
      'user-agent': 'git/2.43.0',
      accept: 'application/x-git-upload-pack-result',
    };
    req.pipe = vi.fn(PassThrough.prototype.pipe);

    res = {
      set: vi.fn().mockReturnThis(),
      status: vi.fn().mockReturnThis(),
      send: vi.fn(),
      end: vi.fn(),
    };

    next = vi.fn();
  });

  it('skips non-pack posts', async () => {
    req.method = 'GET';
    await extractRawBody(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(rawBody).not.toHaveBeenCalled();
  });

  it('extracts raw body and sets bodyRaw property', async () => {
    req.write('abcd');
    req.end();

    await extractRawBody(req, res, next);

    expect(rawBody).toHaveBeenCalledOnce();
    expect(chain.executeChain).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledOnce();
    expect(req.bodyRaw).toBeDefined();
    expect(typeof req.pipe).toBe('function');
  });

  it('replays the buffered body when the request is piped to the upstream proxy', async () => {
    req.end();
    await extractRawBody(req, res, next);

    const upstream = new PassThrough();
    const chunks: Buffer[] = [];
    upstream.on('data', (chunk: Buffer) => chunks.push(chunk));
    await new Promise<void>((resolve) => {
      upstream.on('end', resolve);
      req.pipe(upstream);
    });

    expect(Buffer.concat(chunks).toString()).toBe('payload');
  });

  it('buffers with the configured pack size limit', async () => {
    req.end();
    await extractRawBody(req, res, next);
    expect((rawBody as Mock).mock.calls[0][1]).toEqual({ limit: 1024 });
  });

  it('rejects a pack POST with a non-git User-Agent before reading the body', async () => {
    req.headers['user-agent'] = 'curl/8.0';

    await extractRawBody(req, res, next);

    expect(rawBody).not.toHaveBeenCalled();
    expect(req.pipe).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(res.set).toHaveBeenCalledWith('connection', 'close');
    expect(res.send).toHaveBeenCalledWith(expect.stringContaining('Invalid request received'));
  });

  it('rejects a pack POST without a git Accept header before reading the body', async () => {
    delete req.headers.accept;

    await extractRawBody(req, res, next);

    expect(rawBody).not.toHaveBeenCalled();
    expect(req.pipe).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects and audits a push to an unregistered repository before reading the body', async () => {
    req.url = req.originalUrl = '/github.com/evil/unknown.git/git-receive-pack';
    req.headers.accept = 'application/x-git-receive-pack-result';
    req.headers['content-type'] = 'application/x-git-receive-pack-request';

    await extractRawBody(req, res, next);

    expect(db.getRepoByUrl).toHaveBeenCalledWith('https://github.com/evil/unknown.git');
    expect(rawBody).not.toHaveBeenCalled();
    expect(req.pipe).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith(expect.stringContaining('not in the authorised'));
    expect(db.writeAudit).toHaveBeenCalledOnce();
    const audited = (db.writeAudit as Mock).mock.calls[0][0];
    expect(audited.type).toBe('push');
    expect(audited.error).toBe(true);
    expect(audited.url).toContain('/evil/unknown.git');
  });

  it('rejects a pull from an unregistered repository without auditing it', async () => {
    req.url = req.originalUrl = '/github.com/evil/unknown.git/git-upload-pack';
    req.headers['content-type'] = 'application/x-git-upload-pack-request';

    await extractRawBody(req, res, next);

    expect(rawBody).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith(expect.stringContaining('not in the authorised'));
    expect(db.writeAudit).not.toHaveBeenCalled();
  });

  it('rejects with 413 when Content-Length exceeds the limit before reading the body', async () => {
    req.headers['content-length'] = '1025';

    await extractRawBody(req, res, next);

    expect(rawBody).not.toHaveBeenCalled();
    expect(req.pipe).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(413);
  });

  it('rejects with 413 when the streamed body exceeds the limit', async () => {
    const tooLarge = Object.assign(new Error('request entity too large'), {
      type: 'entity.too.large',
    });
    (rawBody as Mock).mockRejectedValueOnce(tooLarge);
    req.end();

    await extractRawBody(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(req.bodyRaw).toBeUndefined();
    expect(res.status).toHaveBeenCalledWith(413);
  });
});

describe('isPackPost()', () => {
  it('returns true for git-upload-pack POST', () => {
    expect(isPackPost({ method: 'POST', url: '/a/b.git/git-upload-pack' } as Request)).toBe(true);
  });

  it('returns true for git-upload-pack POST, with a gitlab style multi-level org', () => {
    expect(
      isPackPost({ method: 'POST', url: '/a/bee/sea/dee.git/git-upload-pack' } as Request),
    ).toBe(true);
  });

  it('returns true for git-upload-pack POST, with a bare (no org) repo URL', () => {
    expect(isPackPost({ method: 'POST', url: '/a.git/git-upload-pack' } as Request)).toBe(true);
  });

  it('returns false for other URLs', () => {
    expect(isPackPost({ method: 'POST', url: '/info/refs' } as Request)).toBe(false);
  });
});
