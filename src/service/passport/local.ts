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

import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { IVerifyOptions, Strategy as LocalStrategy } from 'passport-local';
import type { PassportStatic } from 'passport';
import * as db from '../../db';
import { serverConfig } from '../../config/env';

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

/**
 * Bootstrap the default admin account.
 *
 * The admin password is sourced from the `GIT_PROXY_ADMIN_PASSWORD` environment
 * variable when set. Otherwise a cryptographically-random password is generated
 * and logged once, on first creation only, so it never ships a guessable
 * default. The account is only created when it does not already exist, so
 * restarts never reset or duplicate it.
 */
export const createDefaultAdmin = async () => {
  const existing = await db.findUser('admin');
  if (existing) {
    return;
  }

  const envPassword = serverConfig.GIT_PROXY_ADMIN_PASSWORD;
  const generated = !envPassword;
  const password = envPassword || crypto.randomBytes(24).toString('base64url');

  await db.createUser('admin', password, 'admin@place.com', 'none', true);

  if (generated) {
    console.warn(
      `WARNING: GIT_PROXY_ADMIN_PASSWORD is not set. A random password was ` +
        `generated for the default 'admin' account:\n\n  ${password}\n\n` +
        `Store it securely and change it after first login. Set ` +
        `GIT_PROXY_ADMIN_PASSWORD to control this password.`,
    );
  }
};
