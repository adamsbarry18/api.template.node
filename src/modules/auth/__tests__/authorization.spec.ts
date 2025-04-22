import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import app from '@/app';
import { adminToken } from '@/tests/setup';

describe('Authorization API', () => {
  let testUserId: number;
  const testEmail = `auth-test-user-${Date.now()}@yopmail.com`;

  beforeAll(async () => {
    // Crée un utilisateur pour les tests d'authorizations
    const res = await request(app)
      .post('/api/v1/users')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        email: testEmail,
        name: 'AuthTest',
        surname: 'User',
        password: 'TotoLeTesteur1!',
        level: 0,
      });
    expect(res.status).toBe(201);
    testUserId = res.body.data.id;
  });

  afterAll(async () => {
    // Supprime l'utilisateur de test (ignore l'erreur si déjà supprimé)
    await request(app)
      .delete(`/api/v1/users/${testUserId}`)
      .set('Authorization', `Bearer ${adminToken}`);
  });

  it('GET /authorization/features should return all features', async () => {
    const res = await request(app)
      .get('/api/v1/authorization/features')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toBeDefined();
    expect(typeof res.body.data).toBe('object');
    // Vérifie qu'il y a au moins une feature
    expect(Object.keys(res.body.data).length).toBeGreaterThan(0);
  });

  it('GET /authorization/features should return 401 without token', async () => {
    const res = await request(app)
      .get('/api/v1/authorization/features');
    expect(res.status).toBe(401);
  });

  it('GET /authorization/levels should return authorizations by level', async () => {
    const res = await request(app)
      .get('/api/v1/authorization/levels')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toBeDefined();
    expect(typeof res.body.data).toBe('object');
    expect(Object.keys(res.body.data).length).toBeGreaterThan(0);
  });

  it('GET /authorization/levels/:level should return authorizations for a level', async () => {
    const res = await request(app)
      .get('/api/v1/authorization/levels/0')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toBeDefined();
    expect(typeof res.body.data).toBe('object');
  });

  it('GET /authorization/users/:userId should return user authorizations', async () => {
    const res = await request(app)
      .get(`/api/v1/authorization/users/${testUserId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('authorisation');
    expect(res.body.data).toHaveProperty('level');
    expect(typeof res.body.data.authorisation).toBe('object');
    expect(typeof res.body.data.level).toBe('number');
  });

  it('GET /authorization/users/:userId should return 404 for unknown user', async () => {
    const res = await request(app)
      .get('/api/v1/authorization/users/999999')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(404);
  });

  it('GET /authorization/users/:userId should return 401 without token', async () => {
    const res = await request(app)
      .get(`/api/v1/authorization/users/${testUserId}`);
    expect(res.status).toBe(401);
  });

  it('POST /authorization/users/:userId/temporary should create a temporary authorization', async () => {
    const expire = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const res = await request(app)
      .post(`/api/v1/authorization/users/${testUserId}/temporary`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ expire, level: 2 });
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('success', true);
  });

  it('POST /authorization/users/:userId/temporary should 404 for unknown user', async () => {
    const res = await request(app)
      .post('/api/v1/authorization/users/999999/temporary')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ expire: new Date().toISOString(), level: 1 });
    expect(res.status).toBe(404);
  });

  it('POST /authorization/users/:userId/temporary should 401 without token', async () => {
    const res = await request(app)
      .post(`/api/v1/authorization/users/${testUserId}/temporary`)
      .send({ expire: new Date().toISOString(), level: 1 });
    expect(res.status).toBe(401);
  });

  it('PUT /authorization/users/:userId should update user authorization', async () => {
    const res = await request(app)
      .put(`/api/v1/authorization/users/${testUserId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ level: 1, authorisationOverrides: null });
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('success', true);
  });

  it('PUT /authorization/users/:userId should 404 for unknown user', async () => {
    const res = await request(app)
      .put('/api/v1/authorization/users/999999')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ level: 1 });
    expect(res.status).toBe(404);
  });

  it('PUT /authorization/users/:userId should 401 without token', async () => {
    const res = await request(app)
      .put(`/api/v1/authorization/users/${testUserId}`)
      .send({ level: 1 });
    expect(res.status).toBe(401);
  });

  it('DELETE /authorization/users/:userId should reset user authorizations', async () => {
    const res = await request(app)
      .delete(`/api/v1/authorization/users/${testUserId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('success', true);
  });

  it('DELETE /authorization/users/:userId should 404 for unknown user', async () => {
    const res = await request(app)
      .delete('/api/v1/authorization/users/999999')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(404);
  });

  it('DELETE /authorization/users/:userId should 401 without token', async () => {
    const res = await request(app)
      .delete(`/api/v1/authorization/users/${testUserId}`);
    expect(res.status).toBe(401);
  });
});
