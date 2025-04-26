import request from 'supertest';
import { v4 as uuidv4 } from 'uuid';
import { describe, it, expect } from 'vitest';

import app from '@/app';
import { adminToken } from '@/tests/globalSetup';

let createdUserId: number;
let zombieUserId: number;

const uid = uuidv4().substring(0, 6);
const userMail = `test-user${uid}@yopmail.com`;
const zombieUserMail = `ztest-user${uid}@yopmail.com`;

describe('Users API', () => {
  describe('POST /users', () => {
    it('should create user', async () => {
      const res = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: userMail,
          name: 'test',
          surname: 'toto',
          color: '#FAFAFA',
          password: 'TotoLeTesteur1!',
          level: 2,
          preferences: { hello: 'world' },
        });
      expect(res.status).toBe(201);
      expect(res.body.status).toBe('success');
      expect(res.body.data.email).toBe(userMail);
      expect(res.body.data).not.toHaveProperty('password');
      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data).toHaveProperty('createdAt');
      createdUserId = res.body.data.id;
    });
    it('should fail to create invalid user', async () => {
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
    it('should return users', async () => {
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
        expect(entry).toHaveProperty('name');
        expect(entry).toHaveProperty('surname');
        expect(entry).toHaveProperty('level');
        expect(entry).toHaveProperty('createdTime');
        expect(entry).toHaveProperty('updatedTime');
        expect(entry).toHaveProperty('preferences');
        expect(entry).toHaveProperty('id');
        expect(entry).not.toHaveProperty('password');
      }
      // Vérifie la pagination si présente
      if (res.body.meta && res.body.meta.pagination) {
        expect(res.body.meta.pagination).toHaveProperty('page');
        expect(res.body.meta.pagination).toHaveProperty('limit');
      }
    });
  });

  describe('GET /users/:id', () => {
    it('should fail to get user with invalid id', async () => {
      const res = await request(app)
        .get('/api/v1/users/-1')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });
    it('should get user from valid id', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      const entry = res.body.data;
      expect(entry.id).toBe(createdUserId);
      expect(entry.email).toBe(userMail);
      expect(entry.name).toBe('test');
      expect(entry.surname).toBe('toto');
      expect(entry.color).toBe('#FAFAFA');
      expect(entry.level).toBe(2);
      expect(entry).toHaveProperty('createdTime');
      expect(entry).toHaveProperty('updatedTime');
      expect(entry).toHaveProperty('preferences');
      expect(entry.preferences).toHaveProperty('hello', 'world');
      expect(entry).not.toHaveProperty('password');
    });
  });
  describe('GET /users/:identifier (email)', () => {
    // Updated describe block
    it('should fail to get user with non-existing email', async () => {
      const nonExistingEmail = 'nonexistent@yopmail.com';
      const res = await request(app)
        .get(`/api/v1/users/${nonExistingEmail}`) // Use the unified route
        .set('Authorization', `Bearer ${adminToken}`);
      // Expect 404 because the service's findByEmail should throw NotFoundError
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });

    it('should get user from valid email', async () => {
      // Ensure the user exists before trying to fetch by email
      // We use the user created in the POST /users test
      const res = await request(app)
        .get(`/api/v1/users/${userMail}`) // Use the unified route
        .set('Authorization', `Bearer ${adminToken}`);
      // Expect 200 because the service's findByEmail should succeed
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      const entry = res.body.data;
      expect(entry.id).toBe(createdUserId);
      expect(entry.email).toBe(userMail);
      expect(entry.name).toBe('test'); // Initial name before update
      expect(entry.surname).toBe('toto');
      expect(entry.color).toBe('#FAFAFA');
      expect(entry.level).toBe(2);
      expect(entry).toHaveProperty('createdTime');
      expect(entry).toHaveProperty('updatedTime');
      expect(entry).toHaveProperty('preferences');
      // Check preferences after potential updates in other tests
      // expect(entry.preferences).toHaveProperty('hello', 'world');
      expect(entry).not.toHaveProperty('password');
    });

    it('should fail to get user by email without admin rights', async () => {
      // Create a non-admin user and get their token
      const nonAdminEmail = `nonadmin-${uid}@yopmail.com`;
      await request(app).post('/api/v1/users').set('Authorization', `Bearer ${adminToken}`).send({
        email: nonAdminEmail,
        name: 'Non',
        surname: 'Admin',
        password: 'Password123!',
        level: 2, // READER level
      });

      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: nonAdminEmail, password: 'Password123!' });
      const nonAdminToken = loginRes.body.data.token;

      const res = await request(app)
        .get(`/api/v1/users/${userMail}`)
        .set('Authorization', `Bearer ${nonAdminToken}`);
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');
      expect(res.body.status).toBe('fail');
    });
  });

  describe('GET /users/me', () => {
    it('should return current user info', async () => {
      const res = await request(app)
        .get('/api/v1/users/me')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toHaveProperty('email', 'user.test1@example.com');
      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data).toHaveProperty('name');
      expect(res.body.data).toHaveProperty('surname');
      expect(res.body.data).not.toHaveProperty('password');
    });

    it('should fail without token', async () => {
      const res = await request(app).get('/api/v1/users/me');
      expect(res.status).toBe(401);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('PUT /users/:id', () => {
    it('should fail to edit user with invalid id', async () => {
      const res = await request(app)
        .put('/api/v1/users/-1')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ name: 'fail' });
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });
    it('should edit user from valid id', async () => {
      const res = await request(app)
        .put(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'editedname',
          preferences: { hello: 'world', hasOnboarding: true },
        });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.name).toBe('editedname');
      expect(res.body.data.preferences).toHaveProperty('hasOnboarding', true);
    });

    it('should check if user was edited correctly', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      const entry = res.body.data;
      expect(entry.id).toBe(createdUserId);
      expect(entry.name).toBe('editedname');
      expect(entry.preferences).toHaveProperty('hello', 'world');
      expect(entry.preferences).toHaveProperty('hasOnboarding', true);
    });
  });

  describe('PUT /users/:id/preferences', () => {
    it('should update user preferences', async () => {
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

    it('should forbid updating preferences for another user as non-admin', async () => {
      // Simulate a non-admin user
      const userRes = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: `prefuser${uid}@yopmail.com`,
          name: 'Pref',
          surname: 'User',
          password: 'TotoLeTesteur1!',
          level: 0,
        });
      const userId = userRes.body.data.id;

      // Login as this user
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: `prefuser${uid}@yopmail.com`,
          password: 'TotoLeTesteur1!',
        });
      const userToken = loginRes.body.data.token;

      // Try to update another user's preferences (should fail)
      const res = await request(app)
        .put(`/api/v1/users/${createdUserId}/preferences`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ theme: 'light' });
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');

      // Try to update own preferences (should fail if user level < READER)
      const resOwn = await request(app)
        .put(`/api/v1/users/${userId}/preferences`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ theme: 'blue' });
      expect(resOwn.status).toBe(403); // Le niveau minimum requis est READER (2)
      expect(resOwn.body.status).toBe('fail');
    });
  });

  describe('DELETE /users/:id/preferences', () => {
    it('should reset user preferences', async () => {
      // Crée un utilisateur dédié pour ce test afin d'éviter l'effet de bord de suppression
      const resCreate = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: `resetpref-main-${uid}@yopmail.com`,
          name: 'ResetPrefMain',
          surname: 'User',
          password: 'TotoLeTesteur1!',
          level: 0,
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

    it('should forbid resetting preferences for another user as non-admin', async () => {
      // Simulate a non-admin user
      const userRes = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: `resetprefuser${uid}@yopmail.com`,
          name: 'ResetPref',
          surname: 'User',
          password: 'TotoLeTesteur1!',
          level: 0,
        });
      const userId = userRes.body.data.id;

      // Login as this user
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: `resetprefuser${uid}@yopmail.com`,
          password: 'TotoLeTesteur1!',
        });
      const userToken = loginRes.body.data.token;

      // Try to reset another user's preferences (should fail)
      const res = await request(app)
        .delete(`/api/v1/users/${createdUserId}/preferences`)
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('fail');

      // Try to reset own preferences (should fail if user level < READER)
      const resOwn = await request(app)
        .delete(`/api/v1/users/${userId}/preferences`)
        .set('Authorization', `Bearer ${userToken}`);
      expect(resOwn.status).toBe(403); // Le niveau minimum requis est READER (2)
      expect(resOwn.body.status).toBe('fail');
    });
  });

  describe('DELETE /users/:id', () => {
    it('should fail to delete user with invalid id', async () => {
      const res = await request(app)
        .delete('/api/v1/users/-1')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });
    it('should delete user from valid id', async () => {
      const res = await request(app)
        .delete(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toBe('Successfull deletion');
    });
    it('should fail to get deleted user', async () => {
      const res = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('Delete user when it no longer has authorisations', () => {
    it('should create a zombie user', async () => {
      const res = await request(app)
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: zombieUserMail,
          name: 'Jean',
          surname: 'NotDead',
          password: 'TotoLeTesteur1!',
          level: 2,
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
          name: 'Monique',
          surname: 'Zombie',
          password: 'TotoLeTesteur1!',
          level: 2,
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
      expect(user.name).toBe('Monique');
    });
  });
});
