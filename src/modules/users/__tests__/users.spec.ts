import { describe, it, beforeAll, afterAll, expect } from 'vitest';
import supertest from 'supertest';
import { v4 as uuidv4 } from 'uuid';
// Assume your main app export is at this path:
import app from '@/app'; // Adjust if your app entry point is elsewhere

const agent = supertest.agent(app);

let createdUserId: number;
let deletedUserId: number;
const uid = uuidv4().substring(0, 6);
const userMail = `testuser${uid}@yopmail.com`;
const userPassword = 'TestUser1!';
const adminToken = process.env.TEST_ADMIN_TOKEN || ''; // Set a valid admin JWT for protected routes

describe('Users API', () => {
  // Helper for authenticated requests
  const authAgent = () => agent.set('Authorization', `Bearer ${adminToken}`);

  beforeAll(async () => {
    // Optionally: seed DB, create admin user, etc.
  });

  afterAll(async () => {
    // Optionally: cleanup DB, close connections, etc.
  });

  it('should create a user', async () => {
    const res = await authAgent()
      .post('/users')
      .send({
        email: userMail,
        name: 'Test',
        surname: 'User',
        color: '#FAFAFA',
        password: userPassword,
        level: 0,
        preferences: { hello: 'world' },
      })
      .expect(201);
    expect(res.body).toHaveProperty('id');
    createdUserId = res.body.id;
    expect(res.body.email).toBe(userMail);
  });

  it('should fail to create invalid user', async () => {
    const res = await authAgent()
      .post('/users')
      .send({ status: 'active', description: 'invalid user' })
      .expect(400);
    expect(res.body).toHaveProperty('error');
  });

  it('should get all users', async () => {
    const res = await authAgent().get('/users').expect(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.some((u: any) => u.email === userMail)).toBe(true);
  });

  it('should get user by id', async () => {
    const res = await authAgent().get(`/users/${createdUserId}`).expect(200);
    expect(res.body).toHaveProperty('id', createdUserId);
    expect(res.body).toHaveProperty('email', userMail);
    expect(res.body).toHaveProperty('name', 'Test');
    expect(res.body).toHaveProperty('surname', 'User');
    expect(res.body).toHaveProperty('color', '#FAFAFA');
    expect(res.body).toHaveProperty('preferences');
    expect(res.body.preferences).toHaveProperty('hello', 'world');
  });

  it('should fail to get user with invalid id', async () => {
    await authAgent().get('/users/-1').expect(404);
  });

  it('should update user', async () => {
    const res = await authAgent()
      .patch(`/users/${createdUserId}`)
      .send({ name: 'Edited', preferences: { hello: 'world', onboarding: true } })
      .expect(200);
    expect(res.body).toHaveProperty('id', createdUserId);
    expect(res.body).toHaveProperty('name', 'Edited');
    expect(res.body.preferences).toHaveProperty('onboarding', true);
  });

  it('should reset user preferences', async () => {
    const res = await authAgent()
      .post(`/users/${createdUserId}/reset-preferences`)
      .send({})
      .expect(200);
    expect(res.body).toHaveProperty('id', createdUserId);
    expect(res.body.preferences).toBeNull();
  });

  it('should update user password', async () => {
    await authAgent().patch(`/users/${createdUserId}`).send({ password: 'TestUser2!' }).expect(200);
  });

  it('should delete user', async () => {
    await authAgent().delete(`/users/${createdUserId}`).expect(204);
    deletedUserId = createdUserId;
  });

  it('should fail to get deleted user', async () => {
    await authAgent().get(`/users/${deletedUserId}`).expect(404);
  });

  // Add more tests for edge cases, e.g. unauthorized access, forbidden actions, etc.
});
