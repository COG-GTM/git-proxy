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
import { createPublicKey } from 'crypto';
import jwt, { type JwtPayload } from 'jsonwebtoken';

import { JwkKey, JwksResponse, JwtValidationResult } from './types';
import { RoleMapping } from '../../config/generated/config';
import { handleErrorAndLog } from '../../utils/errors';

export const JWKS_HTTP_TIMEOUT_MS = 5_000;
export const JWKS_CACHE_TTL_MS = 10 * 60 * 1000;
export const JWKS_MIN_REFRESH_INTERVAL_MS = 30 * 1000;

type JwksCacheEntry = {
  keys?: JwkKey[];
  fetchedAt: number;
  lastAttemptAt: number;
  lastError?: Error;
  inFlight?: Promise<JwkKey[]>;
};

const jwksCache = new Map<string, JwksCacheEntry>();

/**
 * Clear the in-memory JWKS cache.
 */
export function clearJwksCache(): void {
  jwksCache.clear();
}

async function fetchJwks(authorityUrl: string): Promise<JwkKey[]> {
  try {
    const { data } = await axios.get(`${authorityUrl}/.well-known/openid-configuration`, {
      timeout: JWKS_HTTP_TIMEOUT_MS,
    });
    const jwksUri: string = data.jwks_uri;

    const { data: jwks }: { data: JwksResponse } = await axios.get(jwksUri, {
      timeout: JWKS_HTTP_TIMEOUT_MS,
    });
    if (!Array.isArray(jwks?.keys)) {
      throw new Error('JWKS response does not contain a keys array');
    }
    return jwks.keys;
  } catch (error: unknown) {
    handleErrorAndLog(error, 'Error fetching JWKS');
    throw new Error('Failed to fetch JWKS');
  }
}

/**
 * Obtain the JSON Web Key Set (JWKS) from the OIDC authority.
 *
 * Keys are cached per authority for JWKS_CACHE_TTL_MS. Concurrent callers share a single
 * in-flight fetch, and outbound fetches (including forced refreshes and retries after a
 * failure) happen at most once per JWKS_MIN_REFRESH_INTERVAL_MS per authority.
 * @param {string} authorityUrl the OIDC authority URL. e.g. https://login.microsoftonline.com/{tenantId}
 * @param {boolean} forceRefresh refetch before the TTL expires (e.g. on an unknown key ID)
 * @return {Promise<JwkKey[]>} the JWKS keys
 */
export async function getJwks(authorityUrl: string, forceRefresh = false): Promise<JwkKey[]> {
  const now = Date.now();
  let entry = jwksCache.get(authorityUrl);
  if (!entry) {
    entry = { fetchedAt: 0, lastAttemptAt: 0 };
    jwksCache.set(authorityUrl, entry);
  }

  if (entry.inFlight) {
    return entry.inFlight;
  }

  const fresh = entry.keys && now - entry.fetchedAt < JWKS_CACHE_TTL_MS;
  if (fresh && !forceRefresh) {
    return entry.keys!;
  }

  if (now - entry.lastAttemptAt < JWKS_MIN_REFRESH_INTERVAL_MS) {
    if (entry.keys) {
      return entry.keys;
    }
    throw entry.lastError ?? new Error('Failed to fetch JWKS');
  }

  const cacheEntry = entry;
  cacheEntry.lastAttemptAt = now;
  cacheEntry.inFlight = fetchJwks(authorityUrl)
    .then((keys) => {
      cacheEntry.keys = keys;
      cacheEntry.fetchedAt = Date.now();
      cacheEntry.lastError = undefined;
      return keys;
    })
    .catch((error: Error) => {
      cacheEntry.lastError = error;
      if (cacheEntry.keys) {
        return cacheEntry.keys;
      }
      throw error;
    })
    .finally(() => {
      cacheEntry.inFlight = undefined;
    });

  return cacheEntry.inFlight;
}

/**
 * Validate a JWT token using the OIDC configuration.
 * @param {string} token the JWT token
 * @param {string} authorityUrl the OIDC authority URL
 * @param {string} expectedAudience the expected audience for the token
 * @param {string} clientID the OIDC client ID
 * @param {Function} getJwksInject the getJwks function to use (for dependency injection). Defaults to the built-in getJwks function.
 * @return {Promise<JwtValidationResult>} the verified payload or an error
 */
export async function validateJwt(
  token: string,
  authorityUrl: string,
  expectedAudience: string,
  clientID: string,
  getJwksInject: (authorityUrl: string, forceRefresh?: boolean) => Promise<JwkKey[]> = getJwks,
): Promise<JwtValidationResult> {
  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded !== 'object' || !decoded.header?.kid) {
      throw new Error('Invalid JWT: Missing key ID (kid)');
    }

    const { kid } = decoded.header;
    let jwk = (await getJwksInject(authorityUrl)).find((key) => key.kid === kid);
    if (!jwk) {
      jwk = (await getJwksInject(authorityUrl, true)).find((key) => key.kid === kid);
    }
    if (!jwk) {
      throw new Error('No matching key found in JWKS');
    }

    const pubKey = createPublicKey({
      key: jwk,
      format: 'jwk',
    });

    const verifiedPayload = jwt.verify(token, pubKey, {
      algorithms: ['RS256'],
      issuer: authorityUrl,
      audience: expectedAudience,
    });

    if (typeof verifiedPayload === 'string') {
      throw new Error('Unexpected string payload in JWT');
    }

    if (verifiedPayload.azp && verifiedPayload.azp !== clientID) {
      throw new Error('JWT client ID does not match');
    }

    return { verifiedPayload, error: null };
  } catch (error: unknown) {
    const errorMessage = handleErrorAndLog(error, 'JWT validation failed');
    return { error: errorMessage, verifiedPayload: null };
  }
}

/**
 * Assign roles to the user based on the role mappings provided in the jwtConfig.
 *
 * If no role mapping is provided, the user will not have any roles assigned (i.e. user.admin = false).
 *
 * For example, the following role mapping will assign the "admin" role to users whose "name" claim is "John Doe":
 *
 * {
 *   "admin": {
 *     "name": "John Doe"
 *   }
 * }
 * @param {RoleMapping} roleMapping the role mapping configuration
 * @param {JwtPayload} payload the JWT payload
 * @param {Record<string, any>} user the req.user object to assign roles to
 */
export function assignRoles(
  roleMapping: RoleMapping | undefined,
  payload: JwtPayload,
  user: Record<string, any>,
): void {
  if (!roleMapping) return;

  for (const role of Object.keys(roleMapping)) {
    const claimMap = roleMapping[role];
    const claim = Object.keys(claimMap)[0];
    const value = claimMap[claim];

    if (payload[claim] && payload[claim] === value) {
      user[role] = true;
    }
  }
}
