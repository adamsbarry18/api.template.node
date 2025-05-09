import request from 'supertest';
import { describe, it, expect, beforeAll } from 'vitest';

import app from '@/app';
import { adminToken } from '@/tests/globalSetup';

describe('Authorization API', () => {
  let testUserId: number;
  const testEmail = `auth-test-user-${Date.now()}@mailtrap.com`;

  beforeAll(async () => {
    const res = await request(app)
      .post('/api/v1/users')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        email: testEmail,
        name: 'AuthTest',
        surname: 'User',
        password: 'TotoLeTesteur1!',
        level: 1,
      });
    expect(res.status).toBe(201);
    expect(res.body.data).toHaveProperty('id');
    testUserId = res.body.data.id;
  });

  describe('GET /authorization/features', () => {
    it('should return all features for admin', async () => {
      const res = await request(app)
        .get('/api/v1/authorization/features')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toBeDefined();
      expect(typeof res.body.data).toBe('object');
      expect(Object.keys(res.body.data).length).toBeGreaterThan(0);
    });

    it('should return 401 if no token is provided', async () => {
      const res = await request(app).get('/api/v1/authorization/features');
      expect(res.status).toBe(401);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('GET /authorization/levels', () => {
    it('should return authorizations grouped by level for admin', async () => {
      const res = await request(app)
        .get('/api/v1/authorization/levels')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toBeDefined();
      expect(typeof res.body.data).toBe('object');
      expect(res.body.data).toHaveProperty('1');
      expect(res.body.data).toHaveProperty('2');
      expect(typeof res.body.data['1']).toBe('object');
      expect(Object.keys(res.body.data['1']).length).toBeGreaterThan(0);
    });

    it('should return 401 if no token is provided', async () => {
      const res = await request(app).get('/api/v1/authorization/levels');
      expect(res.status).toBe(401);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('GET /authorization/levels/:level', () => {
    it('should return authorizations for a specific level (e.g., level 1)', async () => {
      const res = await request(app)
        .get('/api/v1/authorization/levels/1')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toBeDefined();
      expect(typeof res.body.data).toBe('object');
      expect(Object.keys(res.body.data).length).toBeGreaterThan(0);
    });

    it('should return 200 and empty data for a non-existent numeric level', async () => {
      const res = await request(app)
        .get('/api/v1/authorization/levels/999')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(typeof res.body.data).toBe('object');
      expect(Object.keys(res.body.data).length).toBeGreaterThan(0);
    });

    it('should return 401 if no token is provided', async () => {
      const res = await request(app).get('/api/v1/authorization/levels/1');
      expect(res.status).toBe(401);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('GET /authorization/users/:userId', () => {
    it('should return authorizations for a specific user', async () => {
      const res = await request(app)
        .get(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toHaveProperty('authorisation');
      expect(res.body.data).toHaveProperty('level');
      expect(typeof res.body.data.authorisation).toBe('object');
      expect(typeof res.body.data.level).toBe('number');
      expect(res.body.data.level).toBe(1);
    });

    it('should return 404 for a non-existent user ID', async () => {
      const res = await request(app)
        .get('/api/v1/authorization/users/999999')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });

    it('should return 401 if no token is provided', async () => {
      const res = await request(app).get(`/api/v1/authorization/users/${testUserId}`);
      expect(res.status).toBe(401);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('POST /authorization/users/:userId/status', () => {
    it('should update user status (level and expiration)', async () => {
      const expire = new Date(Date.now() + 3600 * 1000).toISOString(); // Expires in 1 hour
      const tempLevel = 2;
      const res = await request(app)
        .post(`/api/v1/authorization/users/${testUserId}/status`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ expire, level: tempLevel });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toHaveProperty('success', true);
    });

    it('should accept an technically invalid level (e.g., 99) and update user', async () => {
      const expire = new Date(Date.now() + 3600 * 1000).toISOString();
      const invalidLevel = 99;
      const res = await request(app)
        .post(`/api/v1/authorization/users/${testUserId}/status`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ expire, level: invalidLevel });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');

      const checkRes = await request(app)
        .get(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(checkRes.body.data.level).toBe(invalidLevel);

      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ level: 1 });
    });

    it('should return 404 for a non-existent user ID', async () => {
      const expire = new Date().toISOString();
      const res = await request(app)
        .post('/api/v1/authorization/users/999999/status')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ expire, level: 1 });
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });

    it('should return 401 if no token is provided', async () => {
      const expire = new Date().toISOString();
      const res = await request(app)
        .post(`/api/v1/authorization/users/${testUserId}/status`)
        .send({ expire, level: 1 });
      expect(res.status).toBe(401);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('PUT /authorization/users/:userId', () => {
    const newLevel = 1;
    const overrides = { FEATURE_A: { CREATE: false } };

    it('should update user authorization level', async () => {
      const res = await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ level: newLevel });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toHaveProperty('success', true);

      const checkRes = await request(app)
        .get(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(checkRes.status).toBe(200);
      expect(checkRes.body.data.level).toBe(newLevel);
      expect(checkRes.body.data.authorisation).not.toHaveProperty('FEATURE_A');
    });

    it('should update user authorization overrides', async () => {
      const res = await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ authorisationOverrides: JSON.stringify(overrides) });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toHaveProperty('success', true);

      const checkRes = await request(app)
        .get(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(checkRes.status).toBe(200);
      expect(checkRes.body.data.level).toBe(newLevel);
    });

    it('should accept an technically invalid level (e.g., 99) and update user', async () => {
      const invalidLevel = 99;
      const res = await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ level: invalidLevel });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');

      const checkRes = await request(app)
        .get(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(checkRes.body.data.level).toBe(invalidLevel);
      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ level: 1 });
    });

    it('should return 404 for a non-existent user ID', async () => {
      const res = await request(app)
        .put('/api/v1/authorization/users/999999')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ level: 1 });
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });

    it('should return 401 if no token is provided', async () => {
      const res = await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .send({ level: 1 });
      expect(res.status).toBe(401);
      expect(res.body.status).toBe('fail');
    });
  });

  describe('DELETE /authorization/users/:userId', () => {
    beforeEach(async () => {
      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ level: 2, authorisationOverrides: JSON.stringify({ TEST: { READ: false } }) });
      const checkRes = await request(app)
        .get(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(checkRes.body.data.level).toBe(2);
    });

    it('should reset user authorization overrides but keep level unchanged', async () => {
      const initialLevel = 2;
      const res = await request(app)
        .delete(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toHaveProperty('success', true);

      const checkRes = await request(app)
        .get(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(checkRes.status).toBe(200);
      expect(checkRes.body.data.level).toBe(initialLevel);
      expect(checkRes.body.data.authorisation).not.toHaveProperty('TEST');
    });

    it('should return 404 for a non-existent user ID', async () => {
      const res = await request(app)
        .delete('/api/v1/authorization/users/999999')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
      expect(res.body.status).toBe('fail');
    });

    it('should return 401 if no token is provided', async () => {
      const res = await request(app).delete(`/api/v1/authorization/users/${testUserId}`);
      expect(res.status).toBe(401);
      expect(res.body.status).toBe('fail');
    });
  });
});
