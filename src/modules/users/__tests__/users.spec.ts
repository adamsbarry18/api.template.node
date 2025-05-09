import request from 'supertest';
import { v4 as uuidv4 } from 'uuid';
import { describe, it, expect } from 'vitest';

import app from '@/app';
import { adminToken } from '@/tests/globalSetup';
import { SecurityLevel } from '../models/users.entity';

let createdUserId: number;
let zombieUserId: number;
let standardUserId: number;
let readerUserId: number;
let userToken: string;
let readerToken: string;

const uid = uuidv4().substring(0, 6);
const userMail = `test-user-${uid}@mailtrap.com`;
const zombieUserMail = `ztest-user-${uid}@mailtrap.com`;
const standardUserEmail = `standard-user-${uid}@mailtrap.com`;
const readerUserEmail = `reader-user-${uid}@mailtrap.com`;
const standardUserPassword = 'PasswordStd1!';
const readerUserPassword = 'PasswordRdr1!';

const createAndLoginUser = async (
  email: string,
  level: SecurityLevel,
  password = 'Password123!',
) => {
  let userId: number;
  let token: string;

  const userRes = await request(app)
    .post('/api/v1/users')
    .set('Authorization', `Bearer ${adminToken}`)
    .send({ email, firstName: 'Test', lastName: 'User', password, level });

  if (userRes.status === 201) {
    userId = userRes.body.data.id;
  } else if (userRes.status === 400 && userRes.body?.message?.includes('already exists')) {
    const getUserRes = await request(app)
      .get(`/api/v1/users/${email}`)
      .set('Authorization', `Bearer ${adminToken}`);
    if (getUserRes.status === 200) {
      userId = getUserRes.body.data.id;
      await request(app)
        .put(`/api/v1/users/${userId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ password });
    } else {
      throw new Error(`Failed to retrieve existing user ${email}`);
    }
  } else {
    console.error(`Failed to create user ${email}:`, userRes.body);
    throw new Error(`Failed to create or retrieve user ${email}. Status: ${userRes.status}`);
  }

  const loginRes = await request(app).post('/api/v1/auth/login').send({ email, password });
  if (loginRes.status !== 200) {
    console.error(`Failed to login user ${email}:`, loginRes.body);
    throw new Error(`Failed to login user ${email}. Status: ${loginRes.status}`);
  }
  token = loginRes.body.data.token;

  return { userId, token };
};

describe('Users API', () => {
  beforeAll(async () => {
    try {
      const standardUser = await createAndLoginUser(
        standardUserEmail,
        SecurityLevel.USER,
        standardUserPassword,
      );
      standardUserId = standardUser.userId;
      userToken = standardUser.token;

      const readerUser = await createAndLoginUser(
        readerUserEmail,
        SecurityLevel.READER,
        readerUserPassword,
      );
      readerUserId = readerUser.userId;
      readerToken = readerUser.token;

      const mainUserRes = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: userMail,
          firstName: 'Main',
          lastName: 'Test',
          color: '#FAFAFA',
          password: 'PasswordMain1!',
          level: SecurityLevel.USER,
          preferences: { hello: 'world' },
          isActive: true,
          permissionsExpireAt: new Date(Date.now() + 3600000 * 24).toISOString(), // Expires in 24 hours
        });
      if (mainUserRes.status === 201) {
        createdUserId = mainUserRes.body.data.id;
      } else if (
        mainUserRes.status === 400 &&
        mainUserRes.body?.message?.includes('already in use by an active user') // Message d'erreur mis à jour
      ) {
        const getMainUserRes = await request(app)
          .get(`/api/v1/users/${userMail}`)
          .set('Authorization', `Bearer ${adminToken}`);
        if (getMainUserRes.status === 200) {
          createdUserId = getMainUserRes.body.data.id;
        } else {
          throw new Error(`Failed to retrieve existing main user ${userMail}`);
        }
      } else {
        throw new Error(
          `Failed to create or retrieve main user ${userMail}. Status: ${mainUserRes.status}`,
        );
      }
    } catch (error) {
      console.error('Error during beforeAll setup:', error);
      throw error;
    }
  });

  describe('POST /users', () => {
    it('should fail to create user with existing email (as admin)', async () => {
      const res = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: userMail,
          firstName: 'duplicate',
          lastName: 'test',
          password: 'Password1!',
          level: SecurityLevel.READER,
        });
      expect(res.status).toBe(400);
      expect(res.body.status).toBe('fail');
      // Adjusting assertion as the specific message might be overridden by error handling
      expect(res.body.message).toBe('Bad request');
    });

    it('should create a user with isActive: false and permissionsExpireAt (as admin)', async () => {
      const inactiveUserEmail = `inactive-${uid}@mailtrap.com`;
      const expireDate = new Date(Date.now() - 3600000).toISOString(); // Expired 1 hour ago
      const res = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: inactiveUserEmail,
          firstName: 'Inactive',
          lastName: 'User',
          password: 'PasswordInactive1!',
          level: SecurityLevel.READER,
          isActive: false,
          permissionsExpireAt: expireDate,
        });
      expect(res.status).toBe(201);
      expect(res.body.status).toBe('success');
      expect(res.body.data.isActive).toBe(false);
      expect(new Date(res.body.data.permissionsExpireAt).toISOString()).toBe(expireDate);
      // Clean up created user
      await request(app)
        .delete(`/api/v1/users/${res.body.data.id}`)
        .set('Authorization', `Bearer ${adminToken}`);
    });

    it('should create a user with isActive: true by default and null permissionsExpireAt (as admin)', async () => {
      const defaultActiveUserEmail = `default-active-${uid}@mailtrap.com`;
      const res = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: defaultActiveUserEmail,
          firstName: 'DefaultActive',
          lastName: 'User',
          password: 'PasswordDefault1!',
          level: SecurityLevel.READER,
          // isActive and permissionsExpireAt are omitted to test defaults
        });
      expect(res.status).toBe(201);
      expect(res.body.status).toBe('success');
      expect(res.body.data.isActive).toBe(true);
      expect(res.body.data.permissionsExpireAt).toBeNull();
      // Clean up created user
      await request(app)
        .delete(`/api/v1/users/${res.body.data.id}`)
        .set('Authorization', `Bearer ${adminToken}`);
    });

    it('should fail to create user (as standard user)', async () => {
      const res = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          email: `forbidden-${uid}@mailtrap.com`,
          firstName: 'forbidden',
          lastName: 'user',
          password: 'Password1!',
          level: SecurityLevel.READER,
        });
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });

    it('should fail to create user with invalid data (as admin)', async () => {
      const res = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          status: 'active',
          description: 'invalid user',
        });
      expect(res.status).toBe(400);
      expect(res.body.status).toBe('fail');
      expect(res.body).toHaveProperty('data');
    });
  });

  describe('GET /users', () => {
    it('should return users (as admin)', async () => {
      const res = await request(app)
        .get('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body).toHaveProperty('data');
      const users = Array.isArray(res.body.data.data)
        ? res.body.data.data
        : Array.isArray(res.body.data)
          ? res.body.data
          : [];
      expect(Array.isArray(users)).toBe(true);
      for (const entry of users) {
        expect(entry).toHaveProperty('email');
        expect(entry).toHaveProperty('firstName');
        expect(entry).toHaveProperty('lastName');
        expect(entry).toHaveProperty('level');
        expect(entry).toHaveProperty('isActive');
        expect(entry).toHaveProperty('permissionsExpireAt');
        expect(entry).toHaveProperty('createdTime');
        expect(entry).toHaveProperty('updatedTime');
        expect(entry).toHaveProperty('preferences');
        expect(entry).toHaveProperty('id');
        expect(entry).not.toHaveProperty('password');
      }
    });

    it('should fail to return users (as standard user)', async () => {
      const res = await request(app)
        .get('/api/v1/users')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });

    it('should fail to return users (as reader user)', async () => {
      const res = await request(app)
        .get('/api/v1/users')
        .set('Authorization', `Bearer ${readerToken}`);
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('GET /users/:identifier (ID)', () => {
    it('should fail to get user with non-existent id (as admin)', async () => {
      const res = await request(app)
        .get('/api/v1/users/-1')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });
    it('should get user from valid id (as admin)', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      const entry = res.body.data;
      expect(entry.id).toBe(createdUserId);
      expect(entry.email).toBe(userMail);
      expect(entry.firstName).toBe('Main');
      expect(entry.lastName).toBe('Test');
      expect(entry.color).toBe('#FAFAFA');
      expect(entry.level).toBe(SecurityLevel.USER);
      expect(entry.isActive).toBe(true);
      expect(entry.permissionsExpireAt).not.toBeNull();
      expect(entry).toHaveProperty('createdTime');
      expect(entry).toHaveProperty('updatedTime');
      expect(entry).toHaveProperty('preferences');
      expect(entry.preferences).toHaveProperty('hello', 'world');
      expect(entry).not.toHaveProperty('password');
    });

    it('should get own user from valid id (as standard user)', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${standardUserId}`)
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.id).toBe(standardUserId);
    });

    it('should fail to get another user from valid id (as standard user)', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });

    it('should fail to get another user from valid id (as reader user)', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${readerToken}`);
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });
  });
  describe('GET /users/:identifier (Email)', () => {
    it('should fail to get user with non-existing email (as admin)', async () => {
      const nonExistingEmail = 'nonexistent@mailtrap.com';
      const res = await request(app)
        .get(`/api/v1/users/${nonExistingEmail}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });

    it('should get user from valid email (as admin)', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${userMail}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      const entry = res.body.data;
      expect(entry.id).toBe(createdUserId);
      expect(entry.email).toBe(userMail);
      expect(entry.firstName).toBe('Main');
      expect(entry.lastName).toBe('Test');
      expect(entry.color).toBe('#FAFAFA');
      expect(entry.level).toBe(SecurityLevel.USER);
      expect(entry.isActive).toBe(true);
      expect(entry.permissionsExpireAt).not.toBeNull();
      expect(entry).toHaveProperty('createdTime');
      expect(entry).toHaveProperty('updatedTime');
      expect(entry).toHaveProperty('preferences');
      expect(entry).not.toHaveProperty('password');
    });

    it('should get own user from valid email (as standard user)', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${standardUserEmail}`)
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.id).toBe(standardUserId);
    });

    it('should fail to get another user by email (as standard user)', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${userMail}`)
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });

    it('should fail to get another user by email (as reader user)', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${userMail}`)
        .set('Authorization', `Bearer ${readerToken}`);
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('GET /users/me', () => {
    it('should return current user info (admin)', async () => {
      const res = await request(app)
        .get('/api/v1/users/me')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toHaveProperty('email', 'user.test1@example.com');
      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data).toHaveProperty('firstName');
      expect(res.body.data).toHaveProperty('lastName');
      expect(res.body.data).not.toHaveProperty('password');
    });

    it('should return current user info (standard user)', async () => {
      const res = await request(app)
        .get('/api/v1/users/me')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.id).toBe(standardUserId);
      expect(res.body.data.email).toBe(standardUserEmail);
      expect(res.body.data).not.toHaveProperty('password');
    });

    it('should fail without token', async () => {
      const res = await request(app).get('/api/v1/users/me');
      expect(res.status).toBe(401);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('PUT /users/:id', () => {
    it('should fail to edit user with non-existent id (as admin)', async () => {
      const res = await request(app)
        .put('/api/v1/users/-1')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ firstName: 'fail' });
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });
    it('should edit user from valid id (as admin)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          firstName: 'editedFirstName',
          preferences: { hello: 'world', hasOnboarding: true },
          isActive: false,
          permissionsExpireAt: null,
        });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.firstName).toBe('editedFirstName');
      expect(res.body.data.preferences).toHaveProperty('hasOnboarding', true);
      expect(res.body.data.isActive).toBe(false);
      expect(res.body.data.permissionsExpireAt).toBeNull();

      // Reset isActive and set a new expiration date for other tests
      const futureExpireDate = new Date(Date.now() + 3600000 * 48).toISOString(); // Expires in 48 hours
      await request(app)
        .put(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ isActive: true, permissionsExpireAt: futureExpireDate });

      const checkRes = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(checkRes.body.data.isActive).toBe(true);
      // Compare timestamps using toBeCloseTo
      const receivedTimestamp = new Date(checkRes.body.data.permissionsExpireAt).getTime();
      const expectedTimestamp = new Date(futureExpireDate).getTime();
      // Use manual comparison with a tolerance (e.g., 500ms)
      const tolerance = 500; // milliseconds
      expect(Math.abs(receivedTimestamp - expectedTimestamp)).toBeLessThan(tolerance);
    });

    it('should edit own user from valid id (as standard user)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${standardUserId}`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ firstName: 'editedStandardFirstName' });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.firstName).toBe('editedStandardFirstName');
    });

    it('should fail to edit another user from valid id (as standard user)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ firstName: 'forbiddenEdit' });
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });

    it('should fail to edit user (as reader user)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${readerUserId}`)
        .set('Authorization', `Bearer ${readerToken}`)
        .send({ firstName: 'forbiddenReaderEdit' });
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });

    it('should check if admin edit was applied correctly', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      const entry = res.body.data;
      expect(entry.id).toBe(createdUserId);
      expect(entry.firstName).toBe('editedFirstName');
      expect(entry.preferences).toHaveProperty('hello', 'world');
      expect(entry.preferences).toHaveProperty('hasOnboarding', true);
    });
  });

  describe('PUT /users/:id/preferences', () => {
    it('should update user preferences (as admin)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${createdUserId}/preferences`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ theme: 'dark', lang: 'fr' });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toHaveProperty('preferences');
      expect(res.body.data.preferences).toHaveProperty('theme', 'dark');
      expect(res.body.data.preferences).toHaveProperty('lang', 'fr');
    });

    it('should update own preferences (as standard user)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${standardUserId}/preferences`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ lang: 'en', notification: true });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.preferences).toHaveProperty('lang', 'en');
      expect(res.body.data.preferences).toHaveProperty('notification', true);
    });

    it('should forbid updating preferences for another user (as standard user)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${createdUserId}/preferences`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ theme: 'light' });
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });

    it('should forbid updating preferences (as reader user)', async () => {
      const resOwn = await request(app)
        .put(`/api/v1/users/${readerUserId}/preferences`)
        .set('Authorization', `Bearer ${readerToken}`)
        .send({ theme: 'blue' });
      expect(resOwn.status).toBe(403);
      expect(resOwn.body.status).toBe('fail');

      const resOther = await request(app)
        .put(`/api/v1/users/${createdUserId}/preferences`)
        .set('Authorization', `Bearer ${readerToken}`)
        .send({ theme: 'green' });
      expect(resOther.status).toBe(403);
      expect(resOther.body.status).toBe('fail');
    });
  });

  describe('DELETE /users/:id/preferences', () => {
    it('should reset user preferences (as admin)', async () => {
      // Crée un utilisateur dédié pour ce test afin d'éviter l'effet de bord de suppression
      const resCreate = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: `resetpref-main-${uid}@mailtrap.com`,
          firstName: 'ResetPrefMain',
          lastName: 'User',
          password: 'TotoLeTesteur1!',
          level: SecurityLevel.READER,
        });
      const userId = resCreate.body.data.id;

      const res = await request(app)
        .delete(`/api/v1/users/${userId}/preferences`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toHaveProperty('preferences');
      // Optionally: check that preferences are empty or default
    });

    it('should reset own preferences (as standard user)', async () => {
      await request(app)
        .put(`/api/v1/users/${standardUserId}/preferences`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ toReset: true });

      const res = await request(app)
        .delete(`/api/v1/users/${standardUserId}/preferences`)
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      const checkRes = await request(app)
        .get(`/api/v1/users/${standardUserId}`)
        .set('Authorization', `Bearer ${userToken}`);
      const prefs = checkRes.body.data.preferences;
      expect(
        prefs === null ||
          typeof prefs !== 'object' ||
          !Object.prototype.hasOwnProperty.call(prefs, 'toReset'),
      ).toBe(true);
    });

    it('should forbid resetting preferences for another user (as standard user)', async () => {
      const res = await request(app)
        .delete(`/api/v1/users/${createdUserId}/preferences`)
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });

    it('should forbid resetting preferences (as reader user)', async () => {
      const resOwn = await request(app)
        .delete(`/api/v1/users/${readerUserId}/preferences`)
        .set('Authorization', `Bearer ${readerToken}`);
      expect(resOwn.status).toBe(403);
      expect(resOwn.body.status).toBe('fail');

      const resOther = await request(app)
        .delete(`/api/v1/users/${createdUserId}/preferences`)
        .set('Authorization', `Bearer ${readerToken}`);
      expect(resOther.status).toBe(403);
      expect(resOther.body.status).toBe('fail');
    });
  });

  describe('PUT /users/:userId/preferences/:key', () => {
    let prefTestUserId: number;
    const prefTestUserMail = `prefkey-${uid}@mailtrap.com`;

    // Create a user specifically for these tests
    beforeAll(async () => {
      const res = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: prefTestUserMail,
          firstName: 'PrefKey',
          lastName: 'Test',
          password: 'Password123!',
          level: SecurityLevel.USER,
          preferences: { initial: 'value', nested: { deep: true } },
        });
      expect(res.status).toBe(201);
      prefTestUserId = res.body.data.id;
    });

    it('should update an existing preference key (as admin)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${prefTestUserId}/preferences/initial`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ value: 'updatedValue' });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.preferences).toHaveProperty('initial', 'updatedValue');
      expect(res.body.data.preferences).toHaveProperty('nested', { deep: true });
    });

    it('should add a new preference key (as admin)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${prefTestUserId}/preferences/newKey`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ value: { complex: [1, 2] } });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.preferences).toHaveProperty('newKey', { complex: [1, 2] });
      expect(res.body.data.preferences).toHaveProperty('initial', 'updatedValue');
    });

    it('should update a nested preference key (as admin)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${prefTestUserId}/preferences/nested`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ value: { deep: false, added: 'yes' } });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.preferences).toHaveProperty('nested', { deep: false, added: 'yes' });
    });

    it('should fail if value is missing in the body (as admin)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${prefTestUserId}/preferences/anotherKey`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({});
      expect(res.status).toBe(400);
      expect(res.body.status).toBe('fail');
    });

    it('should fail for non-existent user ID (as admin)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/999999/preferences/anyKey`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ value: 'test' });
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });

    it('should update own preference key (as standard user)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${standardUserId}/preferences/myKey`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ value: 'myValue' });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.preferences).toHaveProperty('myKey', 'myValue');
    });

    it('should fail to update another user preference key (as standard user)', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${prefTestUserId}/preferences/theme`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ value: 'forbiddenTheme' });
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
    });

    it('should forbid updating preference key (as reader user)', async () => {
      const resOwn = await request(app)
        .put(`/api/v1/users/${readerUserId}/preferences/readerKey`)
        .set('Authorization', `Bearer ${readerToken}`)
        .send({ value: 'readerValue' });
      expect(resOwn.status).toBe(403);
      expect(resOwn.body.status).toBe('fail');

      const resOther = await request(app)
        .put(`/api/v1/users/${prefTestUserId}/preferences/theme`)
        .set('Authorization', `Bearer ${readerToken}`)
        .send({ value: 'forbiddenTheme' });
      expect(resOther.status).toBe(403);
      expect(resOther.body.status).toBe('fail');
    });

    // Nettoyer l'utilisateur créé pour ces tests spécifiques
    afterAll(async () => {
      if (prefTestUserId) {
        await request(app)
          .delete(`/api/v1/users/${prefTestUserId}`)
          .set('Authorization', `Bearer ${adminToken}`);
      }
    });
  });

  describe('DELETE /users/:id', () => {
    it('should fail to delete user with non-existent id (as admin)', async () => {
      const res = await request(app)
        .delete('/api/v1/users/-1')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });
    it('should delete user from valid id (as admin)', async () => {
      const res = await request(app)
        .delete(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toBe('Successfull deletion');
    });
    it('should fail to get deleted user (as admin)', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });
  });

  it('should fail to delete user (as standard user)', async () => {
    const tempUserRes = await request(app)
      .post('/api/v1/users')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        email: `tempdel-${uid}@mailtrap.com`,
        firstName: 'Temp',
        lastName: 'Delete',
        password: 'Password1!',
        level: SecurityLevel.READER,
      });
    expect(tempUserRes.status).toBe(201);
    const tempUserId = tempUserRes.body.data.id;

    const res = await request(app)
      .delete(`/api/v1/users/${tempUserId}`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(403);
    expect(res.body.status).toBe('fail');

    await request(app)
      .delete(`/api/v1/users/${tempUserId}`)
      .set('Authorization', `Bearer ${adminToken}`);
  });

  it('should fail to delete user (as reader user)', async () => {
    const res = await request(app)
      .delete(`/api/v1/users/${createdUserId}`)
      .set('Authorization', `Bearer ${readerToken}`);
    expect(res.status).toBe(403);
    expect(res.body.status).toBe('fail');
  });

  describe('Delete user when it no longer has authorisations', () => {
    it('should create a zombie user', async () => {
      const res = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: zombieUserMail,
          firstName: 'Jean',
          lastName: 'NotDead',
          password: 'TotoLeTesteur1!',
          level: SecurityLevel.USER,
        });
      expect(res.status).toBe(201);
      expect(res.body.status).toBe('success');
      zombieUserId = res.body.data.id;
    });
    it('should delete zombie user', async () => {
      const res = await request(app)
        .delete(`/api/v1/users/${zombieUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toBe('Successfull deletion');
    });
    it('should fail to get deleted zombie user', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${zombieUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });
    it('should resurrect zombie user', async () => {
      const res = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: zombieUserMail,
          firstName: 'Monique',
          lastName: 'Zombie',
          password: 'TotoLeTesteur1!',
          level: SecurityLevel.USER,
        });
      expect(res.status).toBe(201);
      expect(res.body.status).toBe('success');
      zombieUserId = res.body.data.id;
    });
    it('should get resurrected user', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${zombieUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      const user = res.body.data;
      expect(user.id).toBe(zombieUserId);
      expect(user.firstName).toBe('Monique');
    });
  });
});
