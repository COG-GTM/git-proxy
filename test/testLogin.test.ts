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

import request from 'supertest';
import { beforeAll, afterAll, beforeEach, describe, it, expect } from 'vitest';
import * as db from '../src/db';
import { Service } from '../src/service';
import { Proxy } from '../src/proxy';
import { Express } from 'express';

describe('login', () => {
  let app: Express;

  const loginAsAdmin = async (): Promise<string> => {
    const res = await request(app).post('/api/auth/login').send({
      username: 'admin',
      password: 'admin',
    });
    expect(res.status).toBe(200);
    expect(res.headers['set-cookie']).toBeDefined();

    let cookie = '';
    (res.headers['set-cookie'] as unknown as string[]).forEach((x: string) => {
      if (x.startsWith('connect')) {
        cookie = x.split(';')[0];
      }
    });
    return cookie;
  };

  beforeAll(async () => {
    app = await Service.start(new Proxy());
    await db.deleteUser('login-test-user');
  });

  describe('test login / logout', () => {
    it('should get 401 if not logged in', async () => {
      const res = await request(app).get('/api/auth/profile');
      expect(res.status).toBe(401);
    });

    it('should be able to login', async () => {
      const cookie = await loginAsAdmin();
      expect(cookie).toBeTruthy();
    });

    it('should now be able to access the user metadata', async () => {
      const cookie = await loginAsAdmin();
      const res = await request(app).get('/api/auth/profile').set('Cookie', cookie);
      expect(res.status).toBe(200);
    });

    it('should be able to set the git account', async () => {
      const cookie = await loginAsAdmin();
      const res = await request(app).post('/api/auth/gitAccount').set('Cookie', cookie).send({
        username: 'admin',
        gitAccount: 'new-account',
      });
      expect(res.status).toBe(200);
    });

    it('should throw an error if the username is not provided when setting the git account', async () => {
      const cookie = await loginAsAdmin();
      const res = await request(app).post('/api/auth/gitAccount').set('Cookie', cookie).send({
        gitAccount: 'new-account',
      });
      expect(res.status).toBe(400);
    });

    it('should now be able to logout', async () => {
      const cookie = await loginAsAdmin();
      const res = await request(app).post('/api/auth/logout').set('Cookie', cookie);
      expect(res.status).toBe(200);
    });

    it('test cannot access profile page', async () => {
      // Login, then logout, then verify we can't access profile
      const cookie = await loginAsAdmin();
      await request(app).post('/api/auth/logout').set('Cookie', cookie);
      const res = await request(app).get('/api/auth/profile').set('Cookie', cookie);
      expect(res.status).toBe(401);
    });

    it('should fail to login with invalid username', async () => {
      const res = await request(app).post('/api/auth/login').send({
        username: 'invalid',
        password: 'admin',
      });
      expect(res.status).toBe(401);
    });

    it('should fail to login with invalid password', async () => {
      const res = await request(app).post('/api/auth/login').send({
        username: 'admin',
        password: 'invalid',
      });
      expect(res.status).toBe(401);
    });

    it('should fail to set the git account if the user is not logged in', async () => {
      const res = await request(app).post('/api/auth/gitAccount').send({
        username: 'admin',
        gitAccount: 'new-account',
      });
      expect(res.status).toBe(401);
    });

    it('should fail to get the current user metadata if not logged in', async () => {
      const res = await request(app).get('/api/auth/profile');
      expect(res.status).toBe(401);
    });

    it('should fail to login with invalid credentials', async () => {
      const res = await request(app).post('/api/auth/login').send({
        username: 'admin',
        password: 'invalid',
      });
      expect(res.status).toBe(401);
    });
  });

  describe('test create user', () => {
    beforeEach(async () => {
      await db.deleteUser('newuser');
      await db.deleteUser('nonadmin');
    });

    it('should fail to create user when not authenticated', async () => {
      const res = await request(app).post('/api/auth/create-user').send({
        username: 'newuser',
        password: 'newpass',
        email: 'new@email.com',
        gitAccount: 'newgit',
      });

      expect(res.status).toBe(403);
      expect(res.body.message).toBe('Not authorized to create users');
    });

    it('should fail to create user when not admin', async () => {
      await db.deleteUser('nonadmin');
      await db.createUser('nonadmin', 'nonadmin', 'nonadmin@test.com', 'nonadmin', false);

      const loginRes = await request(app).post('/api/auth/login').send({
        username: 'nonadmin',
        password: 'nonadmin',
      });

      expect(loginRes.status).toBe(200);

      let nonAdminCookie: string;
      (loginRes.headers['set-cookie'] as unknown as string[]).forEach((x: string) => {
        if (x.startsWith('connect')) {
          nonAdminCookie = x.split(';')[0];
        }
      });

      const res = await request(app)
        .post('/api/auth/create-user')
        .set('Cookie', nonAdminCookie!)
        .send({
          username: 'newuser',
          password: 'newpass',
          email: 'new@email.com',
          gitAccount: 'newgit',
        });

      expect(res.status).toBe(403);
      expect(res.body.message).toBe('Not authorized to create users');
    });

    it('should fail to create user with missing required fields', async () => {
      const loginRes = await request(app).post('/api/auth/login').send({
        username: 'admin',
        password: 'admin',
      });

      const adminCookie = loginRes.headers['set-cookie'][0].split(';')[0];

      const res = await request(app).post('/api/auth/create-user').set('Cookie', adminCookie).send({
        username: 'newuser',
        email: 'new@email.com',
        gitAccount: 'newgit',
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBe(
        'Missing required fields: username, password, email, and gitAccount are required',
      );
    });

    it('should successfully create a new user', async () => {
      const loginRes = await request(app).post('/api/auth/login').send({
        username: 'admin',
        password: 'admin',
      });

      const adminCookie = loginRes.headers['set-cookie'][0].split(';')[0];

      const res = await request(app).post('/api/auth/create-user').set('Cookie', adminCookie).send({
        username: 'newuser',
        password: 'newpass',
        email: 'new@email.com',
        gitAccount: 'newgit',
        admin: false,
      });

      expect(res.status).toBe(201);
      expect(res.body.message).toBe('User created successfully');
      expect(res.body.username).toBe('newuser');

      const newUserLoginRes = await request(app).post('/api/auth/login').send({
        username: 'newuser',
        password: 'newpass',
      });

      expect(newUserLoginRes.status).toBe(200);
    });

    it('should fail to create user when username already exists', async () => {
      const loginRes = await request(app).post('/api/auth/login').send({
        username: 'admin',
        password: 'admin',
      });

      const adminCookie = loginRes.headers['set-cookie'][0].split(';')[0];

      const res = await request(app).post('/api/auth/create-user').set('Cookie', adminCookie).send({
        username: 'newuser',
        password: 'newpass',
        email: 'new@email.com',
        gitAccount: 'newgit',
        admin: false,
      });

      expect(res.status).toBe(201);

      const failCreateRes = await request(app)
        .post('/api/auth/create-user')
        .set('Cookie', adminCookie)
        .send({
          username: 'newuser',
          password: 'newpass',
          email: 'new@email.com',
          gitAccount: 'newgit',
          admin: false,
        });

      expect(failCreateRes.status).toBe(500);
      expect(failCreateRes.body.message).toBe('Failed to create user: user newuser already exists');
    });
  });

  describe('test change password', () => {
    const username = 'pwchange-user';
    const originalPassword = 'pwchange-original-pass';
    const newPassword = 'pwchange-new-password-123';

    const loginAs = async (password: string) =>
      request(app).post('/api/auth/login').send({ username, password });

    const cookieFrom = (res: request.Response): string => {
      let cookie = '';
      (res.headers['set-cookie'] as unknown as string[]).forEach((x: string) => {
        if (x.startsWith('connect')) {
          cookie = x.split(';')[0];
        }
      });
      return cookie;
    };

    beforeEach(async () => {
      await db.deleteUser(username);
      await db.createUser(username, originalPassword, 'pwchange@test.com', username, false);
    });

    afterAll(async () => {
      await db.deleteUser(username);
    });

    it('should reject a password change when not logged in', async () => {
      const res = await request(app)
        .post('/api/auth/change-password')
        .send({ currentPassword: originalPassword, newPassword });
      expect(res.status).toBe(401);
    });

    it('should reject a password change with a wrong current password', async () => {
      const cookie = cookieFrom(await loginAs(originalPassword));
      const res = await request(app)
        .post('/api/auth/change-password')
        .set('Cookie', cookie)
        .send({ currentPassword: 'not-the-password', newPassword });
      expect(res.status).toBe(401);
      expect((await loginAs(originalPassword)).status).toBe(200);
    });

    it('should reject missing fields and too-short or unchanged passwords', async () => {
      const cookie = cookieFrom(await loginAs(originalPassword));
      const send = (body: object) =>
        request(app).post('/api/auth/change-password').set('Cookie', cookie).send(body);

      expect((await send({ newPassword })).status).toBe(400);
      expect((await send({ currentPassword: originalPassword, newPassword: 'short' })).status).toBe(
        400,
      );
      expect(
        (await send({ currentPassword: originalPassword, newPassword: originalPassword })).status,
      ).toBe(400);
    });

    it('should change the password so only the new one works', async () => {
      const cookie = cookieFrom(await loginAs(originalPassword));
      const res = await request(app)
        .post('/api/auth/change-password')
        .set('Cookie', cookie)
        .send({ currentPassword: originalPassword, newPassword });
      expect(res.status).toBe(200);

      expect((await loginAs(originalPassword)).status).toBe(401);
      expect((await loginAs(newPassword)).status).toBe(200);
    });
  });

  afterAll(async () => {
    await Service.stop();
  });
});
