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

import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { IVerifyOptions, Strategy as LocalStrategy } from 'passport-local';
import type { PassportStatic } from 'passport';
import * as db from '../../db';

export const type = 'local';

// Dynamic import to always get the current db module instance
// This is necessary for test environments where modules may be reset
const getDb = () => import('../../db');

export const configure = async (passport: PassportStatic): Promise<PassportStatic> => {
  passport.use(
    new LocalStrategy(
      async (
        username: string,
        password: string,
        done: (err: unknown, user?: Partial<db.User>, info?: IVerifyOptions) => void,
      ) => {
        try {
          const dbModule = await getDb();
          const user = await dbModule.findUser(username);
          if (!user) {
            return done(null, undefined, { message: 'Incorrect username.' });
          }

          const passwordCorrect = await bcrypt.compare(password, user.password ?? '');
          if (!passwordCorrect) {
            return done(null, undefined, { message: 'Incorrect password.' });
          }

          return done(null, user);
        } catch (error: unknown) {
          return done(error);
        }
      },
    ),
  );

  passport.serializeUser((user: Partial<db.User>, done) => {
    done(null, user.username);
  });

  passport.deserializeUser(async (username: string, done) => {
    try {
      const dbModule = await getDb();
      const user = await dbModule.findUser(username);
      done(null, user);
    } catch (error: unknown) {
      done(error, null);
    }
  });

  return passport;
};

export const ADMIN_PASSWORD_ENV_VAR = 'GIT_PROXY_ADMIN_PASSWORD';

const DEFAULT_ADMIN_USERNAME = 'admin';
const DEFAULT_ADMIN_EMAIL = 'admin@place.com';

// Credentials seeded by older versions of GitProxy. Warn loudly if any are still usable.
const LEGACY_DEFAULT_CREDENTIALS = [
  { username: 'admin', password: 'admin' },
  { username: 'user', password: 'user' },
];

const generatePassword = (): string => crypto.randomBytes(18).toString('base64url');

const warnOnLegacyDefaultCredentials = async () => {
  for (const { username, password } of LEGACY_DEFAULT_CREDENTIALS) {
    const user = await db.findUser(username);
    if (user?.password && (await bcrypt.compare(password, user.password))) {
      console.warn(
        `WARNING: user "${username}" still has the well-known default password. ` +
          'Change it immediately via POST /api/auth/change-password or delete the account.',
      );
    }
  }
};

/**
 * Bootstrap the initial admin user on first start.
 *
 * The password is taken from the GIT_PROXY_ADMIN_PASSWORD environment variable if set,
 * otherwise a random password is generated and printed once to the log.
 */
export const createDefaultAdmin = async () => {
  const existingAdmin = await db.findUser(DEFAULT_ADMIN_USERNAME);
  if (!existingAdmin) {
    const envPassword = process.env[ADMIN_PASSWORD_ENV_VAR];
    const password = envPassword || generatePassword();
    await db.createUser(DEFAULT_ADMIN_USERNAME, password, DEFAULT_ADMIN_EMAIL, 'none', true);

    if (envPassword) {
      console.log(
        `Created initial admin user "${DEFAULT_ADMIN_USERNAME}" with the password from ${ADMIN_PASSWORD_ENV_VAR}.`,
      );
    } else {
      console.log(
        [
          '========================================================================',
          `Created initial admin user "${DEFAULT_ADMIN_USERNAME}" with a generated password:`,
          `  ${password}`,
          'This password will not be shown again. Change it after first login via',
          'POST /api/auth/change-password.',
          '========================================================================',
        ].join('\n'),
      );
    }
  }

  await warnOnLegacyDefaultCredentials();
};
