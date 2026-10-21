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

import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as config from '../src/config';
import { exchangeToken } from '../src/proxy/tokenExchange';

const externalToken = 'external-test-token';
const internalToken = 'internal-test-pat';
const internalTokenEnv = 'TOKEN_EXCHANGE_TEST_INTERNAL_PAT';
const upstreamHost = 'github.com';

const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex');
const basicHeader = (username: string, token: string): string =>
  `Basic ${Buffer.from(`${username}:${token}`).toString('base64')}`;

const mappedConfig = (overrides: Record<string, unknown> = {}) => ({
  enabled: true,
  mappings: [
    {
      externalTokenSha256: hashToken(externalToken),
      internalTokenEnv,
    },
  ],
  ...overrides,
});

describe('exchangeToken', () => {
  const originalEnvironment = { ...process.env };

  afterEach(() => {
    vi.restoreAllMocks();
    process.env = { ...originalEnvironment };
  });

  it('skips exchange when configuration is disabled or missing', () => {
    const configSpy = vi.spyOn(config, 'getTokenExchange').mockReturnValue({
      enabled: false,
    });
    expect(exchangeToken(basicHeader('externalUser', externalToken), upstreamHost)).toEqual({
      status: 'skipped',
    });

    configSpy.mockReturnValue(undefined);
    expect(exchangeToken(basicHeader('externalUser', externalToken), upstreamHost)).toEqual({
      status: 'skipped',
    });
  });

  it('skips anonymous requests', () => {
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(mappedConfig());

    expect(exchangeToken(undefined, upstreamHost)).toEqual({ status: 'skipped' });
  });

  it('exchanges a matching token', () => {
    process.env[internalTokenEnv] = internalToken;
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(
      mappedConfig({
        mappings: [
          {
            externalTokenSha256: hashToken(externalToken),
            internalTokenEnv,
            internalUsername: 'internalUser',
          },
        ],
      }),
    );

    const result = exchangeToken(basicHeader('externalUser', externalToken), upstreamHost);

    expect(result.status).toBe('exchanged');
    if (result.status === 'exchanged') {
      expect(Buffer.from(result.authorization.slice('Basic '.length), 'base64').toString()).toBe(
        'internalUser:internal-test-pat',
      );
      expect(result.internalUsername).toBe('internalUser');
    }
  });

  it('uses the incoming username when internalUsername is omitted', () => {
    process.env[internalTokenEnv] = internalToken;
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(mappedConfig());

    const result = exchangeToken(basicHeader('externalUser', externalToken), upstreamHost);

    expect(result.status).toBe('exchanged');
    if (result.status === 'exchanged') {
      expect(Buffer.from(result.authorization.slice('Basic '.length), 'base64').toString()).toBe(
        'externalUser:internal-test-pat',
      );
      expect(result.internalUsername).toBe('externalUser');
    }
  });

  it('matches uppercase external token hashes', () => {
    process.env[internalTokenEnv] = internalToken;
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(
      mappedConfig({
        mappings: [
          {
            externalTokenSha256: hashToken(externalToken).toUpperCase(),
            internalTokenEnv,
          },
        ],
      }),
    );

    expect(exchangeToken(basicHeader('externalUser', externalToken), upstreamHost).status).toBe(
      'exchanged',
    );
  });

  it('matches host-scoped mappings case-insensitively', () => {
    process.env[internalTokenEnv] = internalToken;
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(
      mappedConfig({
        mappings: [
          {
            externalTokenSha256: hashToken(externalToken),
            internalTokenEnv,
            hosts: ['github.com'],
          },
        ],
      }),
    );

    expect(exchangeToken(basicHeader('externalUser', externalToken), 'github.com').status).toBe(
      'exchanged',
    );
    expect(exchangeToken(basicHeader('externalUser', externalToken), 'GitHub.com').status).toBe(
      'exchanged',
    );
  });

  it('rejects a credential whose mapping is scoped to a different host', () => {
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(
      mappedConfig({
        mappings: [
          {
            externalTokenSha256: hashToken(externalToken),
            internalTokenEnv,
            hosts: ['github.com'],
          },
        ],
      }),
    );

    expect(exchangeToken(basicHeader('externalUser', externalToken), 'gitlab.example.com')).toEqual(
      {
        status: 'rejected',
        message: 'Token exchange failed: credential not recognised by GitProxy',
      },
    );
  });

  it('allows mappings without hosts for any upstream host', () => {
    process.env[internalTokenEnv] = internalToken;
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(mappedConfig());

    expect(
      exchangeToken(basicHeader('externalUser', externalToken), 'gitlab.example.com').status,
    ).toBe('exchanged');
  });

  it('rejects a mapping with a mismatched external username', () => {
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(
      mappedConfig({
        mappings: [
          {
            externalTokenSha256: hashToken(externalToken),
            externalUsername: 'expectedUser',
            internalTokenEnv,
          },
        ],
      }),
    );

    expect(exchangeToken(basicHeader('otherUser', externalToken), upstreamHost)).toEqual({
      status: 'rejected',
      message: 'Token exchange failed: credential not recognised by GitProxy',
    });
  });

  it('rejects an unmapped token unless allowUnmapped is enabled', () => {
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(mappedConfig());

    expect(exchangeToken(basicHeader('externalUser', 'unmapped-token'), upstreamHost)).toEqual({
      status: 'rejected',
      message: 'Token exchange failed: credential not recognised by GitProxy',
    });

    vi.mocked(config.getTokenExchange).mockReturnValue(mappedConfig({ allowUnmapped: true }));
    expect(exchangeToken(basicHeader('externalUser', 'unmapped-token'), upstreamHost)).toEqual({
      status: 'skipped',
    });
  });

  it('rejects or skips non-Basic authorization depending on allowUnmapped', () => {
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(mappedConfig());

    expect(exchangeToken('Bearer external-test-token', upstreamHost)).toEqual({
      status: 'rejected',
      message: 'Token exchange failed: credential not recognised by GitProxy',
    });

    vi.mocked(config.getTokenExchange).mockReturnValue(mappedConfig({ allowUnmapped: true }));
    expect(exchangeToken('Bearer external-test-token', upstreamHost)).toEqual({
      status: 'skipped',
    });
  });

  it('splits credentials on the first colon only', () => {
    process.env[internalTokenEnv] = internalToken;
    const tokenWithColon = 'external:token:with:colons';
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(
      mappedConfig({
        mappings: [
          {
            externalTokenSha256: hashToken(tokenWithColon),
            internalTokenEnv,
            internalUsername: 'internalUser',
          },
        ],
      }),
    );

    const result = exchangeToken(basicHeader('externalUser', tokenWithColon), upstreamHost);

    expect(result.status).toBe('exchanged');
    if (result.status === 'exchanged') {
      expect(Buffer.from(result.authorization.slice('Basic '.length), 'base64').toString()).toBe(
        'internalUser:internal-test-pat',
      );
    }
  });

  it('rejects when the internal token environment variable is missing without logging credentials', () => {
    const sensitiveExternalToken = 'sensitive-external-token';
    const sensitiveInternalToken = 'sensitive-internal-pat';
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(config, 'getTokenExchange').mockReturnValue(
      mappedConfig({
        mappings: [
          {
            externalTokenSha256: hashToken(sensitiveExternalToken),
            internalTokenEnv,
          },
        ],
      }),
    );

    const result = exchangeToken(basicHeader('externalUser', sensitiveExternalToken), upstreamHost);

    expect(result).toEqual({
      status: 'rejected',
      message:
        'Token exchange is misconfigured for this credential. Please contact an administrator.',
    });
    const loggedOutput = consoleErrorSpy.mock.calls.flat().join(' ');
    expect(loggedOutput).toContain(internalTokenEnv);
    expect(loggedOutput).not.toContain(sensitiveExternalToken);
    expect(loggedOutput).not.toContain(sensitiveInternalToken);
  });
});
