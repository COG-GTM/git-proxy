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

import * as db from '../../db';
import { PassportStatic } from 'passport';
import { getAuthMethods } from '../../config';
import { type UserInfoResponse } from 'openid-client';
import { handleErrorAndLog } from '../../utils/errors';
import { createHash } from 'crypto';

export const type = 'openidconnect';

export const configure = async (passport: PassportStatic): Promise<PassportStatic> => {
  // Use dynamic imports to avoid ESM/CommonJS issues
  const { discovery, fetchUserInfo } = await import('openid-client');
  // @ts-expect-error - throws error due to missing type definitions
  const { Strategy } = await import('openid-client/passport');

  const authMethods = getAuthMethods();
  const oidcConfig = authMethods.find((method) => method.type.toLowerCase() === type)?.oidcConfig;

  if (!oidcConfig || !oidcConfig.issuer) {
    throw new Error('Missing OIDC issuer in configuration');
  }

  const { issuer, clientID, clientSecret, callbackURL, scope } = oidcConfig;

  const server = new URL(issuer);
  let config;

  try {
    config = await discovery(server, clientID, clientSecret);
  } catch (error: unknown) {
    const msg = handleErrorAndLog(error, 'Error during OIDC discovery');
    throw new Error(`OIDC setup error (discovery): ${msg}`);
  }

  try {
    const strategy = new Strategy(
      { callbackURL, config, scope },
      async (tokenSet: any, done: (err: unknown, user?: Partial<db.User>) => void) => {
        const idTokenClaims = tokenSet.claims();
        const expectedSub = idTokenClaims.sub;
        const userInfo = await fetchUserInfo(config, tokenSet.access_token, expectedSub);
        handleUserAuthentication(userInfo, done);
      },
    );

    strategy.currentUrl = function (request: Request) {
      const callbackUrl = new URL(callbackURL);
      const currentUrl = Strategy.prototype.currentUrl.call(this, request);
      currentUrl.host = callbackUrl.host;
      currentUrl.protocol = callbackUrl.protocol;
      return currentUrl;
    };

    passport.use(type, strategy);

    passport.serializeUser((user: Partial<db.User>, done) => {
      done(null, user.oidcId || user.username);
    });

    passport.deserializeUser(async (id: string, done) => {
      try {
        const user = (await db.findUserByOIDC(id)) ?? (await db.findUser(id));
        done(null, user);
      } catch (error: unknown) {
        done(error);
      }
    });

    return passport;
  } catch (error: unknown) {
    const msg = handleErrorAndLog(error, 'Error during OIDC passport setup');
    throw new Error(`OIDC setup error (strategy): ${msg}`);
  }
};

/**
 * Handles user authentication with OIDC.
 * @param {UserInfoResponse} userInfo - The user info response from the OIDC provider
 * @param {Function} done - The callback function to handle the user authentication
 * @return {Promise<void>} - A promise that resolves when the user authentication is complete
 */
export const handleUserAuthentication = async (
  userInfo: UserInfoResponse,
  done: (err: unknown, user?: Partial<db.User>) => void,
): Promise<void> => {
  try {
    if (!userInfo.sub) return done(new Error('No subject found in OIDC profile'));

    const user = await db.findUserByOIDC(userInfo.sub);
    if (user) return done(null, user);

    const email = safelyExtractEmail(userInfo);
    if (!email) return done(new Error('No email found in OIDC profile'));
    if (userInfo.email_verified === false) {
      return done(new Error('OIDC email address is not verified'));
    }

    const existingWithEmail = await db.findUserByEmail(email);
    if (existingWithEmail) {
      if (isUnboundOIDCUser(existingWithEmail)) {
        // Accounts created before the OIDC subject was persisted: bind on exact email match.
        existingWithEmail.oidcId = userInfo.sub;
        await db.updateUser(existingWithEmail);
        return done(null, existingWithEmail);
      }
      return done(new Error(`A user with email ${email} already exists`));
    }

    const username = await getAvailableUsername(email, userInfo.sub);
    await db.createUser(username, '', email, 'Edit me', false, userInfo.sub);

    const created = await db.findUserByOIDC(userInfo.sub);
    return done(null, created ?? { username, email, oidcId: userInfo.sub });
  } catch (error: unknown) {
    const msg = handleErrorAndLog(error, 'Error during OIDC user authentication');
    return done(msg);
  }
};

// createUser stores an explicit null password only for OIDC accounts; AD upserts omit the field.
const isUnboundOIDCUser = (user: db.User): boolean => !user.oidcId && user.password === null;

/**
 * Picks a username for a new OIDC user. Uses the email local part when free, otherwise
 * appends a suffix derived from the OIDC subject so a different identity sharing the
 * same local part never collides with (or squats) an existing account.
 * @param {string} email - The email address from the OIDC profile
 * @param {string} sub - The OIDC subject identifier
 * @return {Promise<string>} - An unused username
 */
export const getAvailableUsername = async (email: string, sub: string): Promise<string> => {
  const base = getUsername(email);
  if (!(await db.findUser(base))) return base;

  const suffixed = `${base}-${createHash('sha256').update(sub).digest('hex').slice(0, 8)}`;
  if (!(await db.findUser(suffixed))) return suffixed;

  throw new Error(`Unable to allocate a unique username for ${email}`);
};

/**
 * Extracts email from OIDC profile.
 * Different providers use different fields to store the email.
 * @param {UserInfoResponse} profile - The user profile from the OIDC provider
 * @return {string | null} - The email address from the profile
 */
export const safelyExtractEmail = (profile: UserInfoResponse): string | null => {
  if (profile.email) {
    return profile.email;
  }
  if (profile.emails && Array.isArray(profile.emails) && profile.emails.length > 0) {
    return (profile.emails[0] as { value: string }).value;
  }
  return null;
};

/**
 * Generates a username from an email address.
 * This helps differentiate users within the specific OIDC provider.
 * Note: This is incompatible with multiple providers. Ideally, users are identified by
 * OIDC ID (requires refactoring the database).
 * @param {string} email - The email address to generate a username from
 * @return {string} - The username generated from the email address
 */
export const getUsername = (email: string): string => {
  return email ? email.split('@')[0] : '';
};
