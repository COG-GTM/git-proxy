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

import axios from 'axios';
import crypto from 'crypto';
import { NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { describe, it, expect, vi, beforeEach, afterEach, MockInstance } from 'vitest';

import {
  assignRoles,
  clearJwksCache,
  getJwks,
  JWKS_CACHE_TTL_MS,
  JWKS_HTTP_TIMEOUT_MS,
  JWKS_MIN_REFRESH_INTERVAL_MS,
  validateJwt,
} from '../src/service/passport/jwtUtils';
import { jwtAuthHandler } from '../src/service/passport/jwtAuthHandler';
import { JwtConfig, RoleMapping } from '../src/config/generated/config';

function generateRsaKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { format: 'pem', type: 'pkcs1' },
    privateKeyEncoding: { format: 'pem', type: 'pkcs1' },
  });
}

function publicKeyToJwk(publicKeyPem, kid = 'test-key') {
  const keyObj = crypto.createPublicKey(publicKeyPem);
  const jwk = keyObj.export({ format: 'jwk' });
  return { ...jwk, kid };
}

describe('JWT', () => {
  beforeEach(() => clearJwksCache());

  describe('getJwks', () => {
    afterEach(() => {
      vi.restoreAllMocks();
      vi.useRealTimers();
    });

    function mockJwksFetch(
      keys: object[] = [{ kid: 'test-key', kty: 'RSA', n: 'abc', e: 'AQAB' }],
    ) {
      return vi
        .spyOn(axios, 'get')
        .mockImplementation(async (url: string) =>
          url.endsWith('/.well-known/openid-configuration')
            ? { data: { jwks_uri: 'https://mock.com/jwks' } }
            : { data: { keys } },
        );
    }

    it('should fetch JWKS keys from authority', async () => {
      const jwksResponse = { keys: [{ kid: 'test-key', kty: 'RSA', n: 'abc', e: 'AQAB' }] };

      const getStub = vi.spyOn(axios, 'get');
      getStub.mockResolvedValueOnce({ data: { jwks_uri: 'https://mock.com/jwks' } });
      getStub.mockResolvedValueOnce({ data: jwksResponse });

      const keys = await getJwks('https://mock.com');
      expect(keys).toEqual(jwksResponse.keys);
    });

    it('should throw error if fetch fails', async () => {
      vi.spyOn(axios, 'get').mockRejectedValue(new Error('Network fail'));
      await expect(getJwks('https://fail.com')).rejects.toThrow('Failed to fetch JWKS');
    });

    it('should set a timeout on both outbound requests', async () => {
      const getStub = mockJwksFetch();
      await getJwks('https://mock.com');

      expect(getStub).toHaveBeenCalledTimes(2);
      for (const call of getStub.mock.calls) {
        expect(call[1]).toEqual(expect.objectContaining({ timeout: JWKS_HTTP_TIMEOUT_MS }));
      }
    });

    it('should cache keys per authority within the TTL', async () => {
      const getStub = mockJwksFetch();

      for (let i = 0; i < 10; i++) {
        await getJwks('https://mock.com');
      }
      expect(getStub).toHaveBeenCalledTimes(2);

      await getJwks('https://other.com');
      expect(getStub).toHaveBeenCalledTimes(4);
    });

    it('should share a single in-flight fetch between concurrent callers', async () => {
      const getStub = mockJwksFetch();
      await Promise.all(Array.from({ length: 20 }, () => getJwks('https://mock.com')));
      expect(getStub).toHaveBeenCalledTimes(2);
    });

    it('should refetch after the TTL expires', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const getStub = mockJwksFetch();

      await getJwks('https://mock.com');
      vi.advanceTimersByTime(JWKS_CACHE_TTL_MS - 1);
      await getJwks('https://mock.com');
      expect(getStub).toHaveBeenCalledTimes(2);

      vi.advanceTimersByTime(2);
      await getJwks('https://mock.com');
      expect(getStub).toHaveBeenCalledTimes(4);
    });

    it('should rate-limit forced refreshes', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const getStub = mockJwksFetch();

      await getJwks('https://mock.com');
      await getJwks('https://mock.com', true);
      await getJwks('https://mock.com', true);
      expect(getStub).toHaveBeenCalledTimes(2);

      vi.advanceTimersByTime(JWKS_MIN_REFRESH_INTERVAL_MS);
      await getJwks('https://mock.com', true);
      expect(getStub).toHaveBeenCalledTimes(4);
    });

    it('should not retry a failed fetch until the refresh interval elapses', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const getStub = vi.spyOn(axios, 'get').mockRejectedValue(new Error('Network fail'));

      await expect(getJwks('https://fail.com')).rejects.toThrow('Failed to fetch JWKS');
      await expect(getJwks('https://fail.com')).rejects.toThrow('Failed to fetch JWKS');
      expect(getStub).toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(JWKS_MIN_REFRESH_INTERVAL_MS);
      await expect(getJwks('https://fail.com')).rejects.toThrow('Failed to fetch JWKS');
      expect(getStub).toHaveBeenCalledTimes(2);
    });

    it('should keep serving cached keys if a refresh fails', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const keys = [{ kid: 'test-key', kty: 'RSA', n: 'abc', e: 'AQAB' }];
      mockJwksFetch(keys);
      await getJwks('https://mock.com');

      vi.restoreAllMocks();
      vi.spyOn(axios, 'get').mockRejectedValue(new Error('Network fail'));
      vi.advanceTimersByTime(JWKS_CACHE_TTL_MS);

      await expect(getJwks('https://mock.com')).resolves.toEqual(keys);
    });
  });

  describe('validateJwt', () => {
    let decodeStub: MockInstance;
    let verifyStub: MockInstance;
    let getJwksStub: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      const jwksResponse = { keys: [{ kid: 'test-key', kty: 'RSA', n: 'abc', e: 'AQAB' }] };
      const axiosStub = vi.spyOn(axios, 'get');

      axiosStub.mockResolvedValueOnce({ data: { jwks_uri: 'https://mock.com/jwks' } });
      axiosStub.mockResolvedValueOnce({ data: jwksResponse });

      getJwksStub = vi.fn().mockResolvedValue(jwksResponse.keys);

      decodeStub = vi.spyOn(jwt, 'decode');
      verifyStub = vi.spyOn(jwt, 'verify');
    });

    afterEach(() => vi.restoreAllMocks());

    it('should validate a correct JWT', async () => {
      const mockJwk = { kid: '123', kty: 'RSA', n: 'abc', e: 'AQAB' };

      decodeStub.mockReturnValue({ header: { kid: '123' } });
      getJwksStub.mockResolvedValue([mockJwk]);
      verifyStub.mockReturnValue({ azp: 'client-id', sub: 'user123' });

      const { verifiedPayload, error } = await validateJwt(
        'fake.token.here',
        'https://issuer.com',
        'client-id',
        'client-id',
        getJwksStub,
      );

      expect(error).toBeNull();
      expect(verifiedPayload?.sub).toBe('user123');
    });

    it('should return error if JWT invalid', async () => {
      decodeStub.mockReturnValue(null);

      const { error } = await validateJwt(
        'bad.token',
        'https://issuer.com',
        'client-id',
        'client-id',
        getJwksStub,
      );
      expect(error).toContain('Invalid JWT');
      expect(getJwksStub).not.toHaveBeenCalled();
    });

    it('should force a single JWKS refresh when the kid is unknown', async () => {
      decodeStub.mockReturnValue({ header: { kid: 'rotated' } });
      getJwksStub.mockResolvedValueOnce([]);
      getJwksStub.mockResolvedValueOnce([{ kid: 'rotated', kty: 'RSA', n: 'abc', e: 'AQAB' }]);
      vi.spyOn(crypto, 'createPublicKey').mockReturnValue({} as crypto.KeyObject);
      verifyStub.mockReturnValue({ azp: 'client-id', sub: 'user123' });

      const { verifiedPayload, error } = await validateJwt(
        'fake.token.here',
        'https://issuer.com',
        'client-id',
        'client-id',
        getJwksStub,
      );

      expect(error).toBeNull();
      expect(verifiedPayload?.sub).toBe('user123');
      expect(getJwksStub).toHaveBeenNthCalledWith(1, 'https://issuer.com');
      expect(getJwksStub).toHaveBeenNthCalledWith(2, 'https://issuer.com', true);
    });

    it('should return error if kid is still unknown after refresh', async () => {
      decodeStub.mockReturnValue({ header: { kid: 'unknown' } });

      const { error } = await validateJwt(
        'fake.token.here',
        'https://issuer.com',
        'client-id',
        'client-id',
        getJwksStub,
      );

      expect(error).toContain('No matching key found in JWKS');
      expect(getJwksStub).toHaveBeenCalledTimes(2);
    });
  });

  describe('validateJwt with real JWT', () => {
    it('should validate a JWT generated with crypto.createPublicKey', async () => {
      const { privateKey, publicKey } = generateRsaKeyPair();
      const jwk = publicKeyToJwk(publicKey, 'my-kid');

      const tokenPayload = jwt.sign(
        {
          sub: 'user123',
          azp: 'client-id',
          admin: 'admin',
        },
        privateKey,
        {
          algorithm: 'RS256',
          issuer: 'https://issuer.com',
          audience: 'client-id',
          keyid: 'my-kid',
        },
      );

      const getJwksStub = vi.fn().mockResolvedValue([jwk]);

      const { verifiedPayload, error } = await validateJwt(
        tokenPayload,
        'https://issuer.com',
        'client-id',
        'client-id',
        getJwksStub,
      );

      expect(error).toBeNull();
      expect(verifiedPayload?.sub).toBe('user123');
      expect(verifiedPayload?.admin).toBe('admin');
    });
  });

  describe('assignRoles', () => {
    it('should assign admin role based on claim', () => {
      const user = { username: 'admin-user', admin: undefined };
      const payload = { admin: 'admin' };
      const mapping = { admin: { admin: 'admin' } };

      assignRoles(mapping, payload, user);
      expect(user.admin).toBe(true);
    });

    it('should assign multiple roles based on claims', () => {
      const user = { username: 'multi-role-user', admin: undefined, editor: undefined };
      const payload = { 'custom-claim-admin': 'custom-value', editor: 'editor' };
      const mapping = {
        admin: { 'custom-claim-admin': 'custom-value' },
        editor: { editor: 'editor' },
      };

      assignRoles(mapping, payload, user);
      expect(user.admin).toBe(true);
      expect(user.editor).toBe(true);
    });

    it('should not assign role if claim mismatch', () => {
      const user = { username: 'basic-user', admin: undefined };
      const payload = { admin: 'nope' };
      const mapping = { admin: { admin: 'admin' } };

      assignRoles(mapping, payload, user);
      expect(user.admin).toBeUndefined();
    });

    it('should not assign role if no mapping provided', () => {
      const user = { username: 'no-role-user', admin: undefined };
      const payload = { admin: 'admin' };

      assignRoles({} as RoleMapping, payload, user);
      expect(user.admin).toBeUndefined();
    });
  });

  describe('jwtAuthHandler', () => {
    let req: any;
    let res: any;
    let next: NextFunction;
    let jwtConfig: JwtConfig;
    let validVerifyResponse: JwtPayload;

    beforeEach(() => {
      req = { header: vi.fn(), isAuthenticated: vi.fn(), user: {} };
      res = { status: vi.fn().mockReturnThis(), send: vi.fn() };
      next = vi.fn();

      jwtConfig = {
        clientID: 'client-id',
        authorityURL: 'https://accounts.google.com',
        expectedAudience: 'expected-audience',
        roleMapping: { admin: { admin: 'admin' } },
      };

      validVerifyResponse = {
        header: { kid: '123' },
        azp: 'client-id',
        sub: 'user123',
        admin: 'admin',
      };
    });

    afterEach(() => vi.restoreAllMocks());

    it('should call next if user is authenticated', async () => {
      req.isAuthenticated.mockReturnValue(true);
      await jwtAuthHandler()(req, res, next);
      expect(next).toHaveBeenCalledOnce();
    });

    it('should return 401 if no token provided', async () => {
      req.header.mockReturnValue(null);
      await jwtAuthHandler(jwtConfig)(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.send).toHaveBeenCalledWith('No token provided\n');
    });

    it('should return 500 if authorityURL not configured', async () => {
      req.header.mockReturnValue('Bearer fake-token');
      jwtConfig.authorityURL = null;
      vi.spyOn(jwt, 'verify').mockReturnValue(validVerifyResponse);

      await jwtAuthHandler(jwtConfig)(req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.send).toHaveBeenCalledWith({ message: 'OIDC authority URL is not configured\n' });
    });

    it('should return 500 if clientID not configured', async () => {
      req.header.mockReturnValue('Bearer fake-token');
      jwtConfig.clientID = null;
      vi.spyOn(jwt, 'verify').mockReturnValue(validVerifyResponse);

      await jwtAuthHandler(jwtConfig)(req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.send).toHaveBeenCalledWith({ message: 'OIDC client ID is not configured\n' });
    });

    it('should return 401 if JWT validation fails', async () => {
      req.header.mockReturnValue('Bearer fake-token');
      vi.spyOn(jwt, 'verify').mockImplementation(() => {
        throw new Error('Invalid token');
      });

      await jwtAuthHandler(jwtConfig)(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.send).toHaveBeenCalledWith(expect.stringMatching(/Invalid JWT:/));
    });

    it('should not contact the authority for malformed tokens', async () => {
      const getStub = vi.spyOn(axios, 'get');

      for (let i = 0; i < 5; i++) {
        req.header.mockReturnValue('x');
        await jwtAuthHandler(jwtConfig)(req, res, next);
      }

      expect(getStub).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should fetch JWKS once for repeated requests with forged tokens', async () => {
      const { publicKey } = generateRsaKeyPair();
      const { privateKey: attackerKey } = generateRsaKeyPair();
      const jwk = publicKeyToJwk(publicKey, 'my-kid');
      const getStub = vi
        .spyOn(axios, 'get')
        .mockImplementation(async (url: string) =>
          url.endsWith('/.well-known/openid-configuration')
            ? { data: { jwks_uri: 'https://accounts.google.com/jwks' } }
            : { data: { keys: [jwk] } },
        );

      for (const kid of ['my-kid', 'random-1', 'random-2', 'my-kid', 'random-3']) {
        const forged = jwt.sign({ sub: 'mallory' }, attackerKey, {
          algorithm: 'RS256',
          issuer: jwtConfig.authorityURL!,
          audience: jwtConfig.expectedAudience!,
          keyid: kid,
        });
        req.header.mockReturnValue(`Bearer ${forged}`);
        await jwtAuthHandler(jwtConfig)(req, res, next);
      }

      expect(getStub).toHaveBeenCalledTimes(2);
      expect(res.status).toHaveBeenCalledTimes(5);
      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });
  });
});
