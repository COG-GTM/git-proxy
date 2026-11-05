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
import express, { NextFunction } from 'express';
import request from 'supertest';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { describe, it, expect, vi, beforeEach, afterEach, MockInstance } from 'vitest';

import { assignRoles, getJwks, validateJwt } from '../src/service/passport/jwtUtils';
import { jwtAuthHandler } from '../src/service/passport/jwtAuthHandler';
import { JwtConfig, RoleMapping } from '../src/config/generated/config';
import * as db from '../src/db';
import pushRouter from '../src/service/routes/push';
import { isAdminUser } from '../src/service/routes/utils';

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
  describe('getJwks', () => {
    afterEach(() => vi.restoreAllMocks());

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

    describe('req.user construction', () => {
      const { privateKey, publicKey } = generateRsaKeyPair();
      const jwk = publicKeyToJwk(publicKey, 'test-kid');

      const signToken = (payload: Record<string, unknown>) =>
        jwt.sign(payload, privateKey, {
          algorithm: 'RS256',
          issuer: jwtConfig.authorityURL!,
          audience: jwtConfig.expectedAudience!,
          keyid: 'test-kid',
        });

      const forgedPayload = {
        azp: 'client-id',
        sub: 'mallory-sub',
        admin: true,
        username: 'approver',
        email: 'approver@example.com',
      };

      beforeEach(() => {
        vi.spyOn(axios, 'get').mockImplementation(async (url: string) =>
          url.endsWith('/.well-known/openid-configuration')
            ? { data: { jwks_uri: 'https://mock.com/jwks' } }
            : { data: { keys: [jwk] } },
        );
      });

      it('should not trust admin or username claims from the token', async () => {
        req.header.mockReturnValue(`Bearer ${signToken(forgedPayload)}`);
        vi.spyOn(db, 'findUserByOIDC').mockResolvedValue(null);

        await jwtAuthHandler(jwtConfig)(req, res, next);

        expect(next).toHaveBeenCalledOnce();
        expect(req.user.admin).toBe(false);
        expect(req.user.username).toBeUndefined();
        expect(req.user.email).toBeUndefined();
        expect(isAdminUser(req.user)).toBe(false);
      });

      it('should resolve username and email from the user database by subject', async () => {
        req.header.mockReturnValue(`Bearer ${signToken(forgedPayload)}`);
        const findSpy = vi.spyOn(db, 'findUserByOIDC').mockResolvedValue({
          username: 'mallory',
          email: 'mallory@example.com',
          admin: false,
        } as any);

        await jwtAuthHandler(jwtConfig)(req, res, next);

        expect(findSpy).toHaveBeenCalledWith('mallory-sub');
        expect(req.user).toEqual({
          sub: 'mallory-sub',
          admin: false,
          username: 'mallory',
          email: 'mallory@example.com',
        });
      });

      it('should grant admin only through roleMapping', async () => {
        req.header.mockReturnValue(
          `Bearer ${signToken({ azp: 'client-id', sub: 'ci-bot', admin: 'admin' })}`,
        );
        vi.spyOn(db, 'findUserByOIDC').mockResolvedValue(null);

        await jwtAuthHandler(jwtConfig)(req, res, next);

        expect(req.user.admin).toBe(true);
        expect(isAdminUser(req.user)).toBe(true);
      });

      it('should return 403 when a forged token tries to authorise a push', async () => {
        vi.spyOn(db, 'findUserByOIDC').mockResolvedValue(null);
        const canApproveSpy = vi.spyOn(db, 'canUserApproveRejectPush').mockResolvedValue(true);
        const authoriseSpy = vi.spyOn(db, 'authorise');

        const app = express();
        app.use(express.json());
        app.use(jwtAuthHandler(jwtConfig));
        app.use('/api/v1/push', pushRouter);

        const response = await request(app)
          .post('/api/v1/push/some-push-id/authorise')
          .set('Authorization', `Bearer ${signToken(forgedPayload)}`)
          .send({
            params: {
              attestation: [
                {
                  label: 'I am happy for this to be pushed to the upstream repository',
                  tooltip: { text: 'tooltip', links: [] },
                  checked: true,
                },
              ],
            },
          });

        expect(response.status).toBe(403);
        expect(canApproveSpy).not.toHaveBeenCalled();
        expect(authoriseSpy).not.toHaveBeenCalled();
      });
    });
  });
});
