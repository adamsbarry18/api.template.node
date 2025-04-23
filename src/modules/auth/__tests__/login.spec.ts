import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '@/app';
import { adminToken } from '@/tests/setup';
import { redisClient } from '@/lib/redis';
import { AppDataSource } from '@/database/data-source';

const testEmail = 'user.test2@example.com';
let currentPassword = '123456PAM$45789asdss';

describe('Auth API', () => {
  let resetCode: string;
  let confirmCode: string;
  let userToken: string;

  beforeAll(async () => {
    // Clean up Redis keys for test user
    if (redisClient) {
      const keys = await redisClient.keys('api:users:*');
      for (const key of keys) {
        await redisClient.del(key);
      }
    }
  });

  describe('POST /auth/login', () => {
    it('should fail with missing credentials', async () => {
      const res = await request(app).post('/api/v1/auth/login').send({});
      expect(res.status).toBe(401);
    });

    it('should fail with wrong credentials', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testEmail, password: 'wrongPassword' });
      expect(res.status).toBe(401);
    });

    it('should login successfully', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testEmail, password: currentPassword });
      expect(res.status).toBe(200);
      expect(res.body.data.token).toBeTruthy();
      userToken = res.body.data.token;
    });
  });

  describe('POST /auth/logout', () => {
    it('should fail without token', async () => {
      const res = await request(app).post('/api/v1/auth/logout');
      expect(res.status).toBe(401);
    });

    it('should logout successfully', async () => {
      const res = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.data.message).toMatch(/Logout successful/i);
    });
  });

  describe('POST /auth/password/reset', () => {
    it('should fail with missing email', async () => {
      const res = await request(app).post('/api/v1/auth/password/reset').send({});
      expect(res.status).toBe(400);
    });

    it('should request password reset and store code in Redis', async () => {
      const res = await request(app)
        .post('/api/v1/auth/password/reset')
        .send({ email: testEmail, language: 'en' });
      expect(res.status).toBe(200);
      expect(res.body.data.message).toMatch(/If your email exists/i);

      // Récupère le code dans Redis (simulateur, car pas d'email réel)
      if (redisClient) {
        const keys = await redisClient.keys('api:users:reset-password:*');
        expect(keys.length).toBeGreaterThan(0);
        resetCode = keys[0].split(':').pop()!;
        const userId = await redisClient.get(keys[0]);
        expect(userId).toBeTruthy();
      }
    });
  });

  describe('POST /auth/password/reset/:code/confirm', () => {
    it('should fail with invalid code', async () => {
      const res = await request(app)
        .post('/api/v1/auth/password/reset/invalidcode/confirm')
        .send({ password: 'SomePwd1!' });
      expect(res.status).toBe(400);
    });

    it('should reset password with code', async () => {
      const newPassword = 'NewTestPwd1!';
      const res = await request(app)
        .post(`/api/v1/auth/password/reset/${resetCode}/confirm`)
        .send({ password: newPassword });
      expect(res.status).toBe(200);
      expect(res.body.data.message).toMatch(/Password reset successful/i);
      currentPassword = newPassword; // <-- MAJ du mot de passe courant

      // Vérifie que le code a été supprimé de Redis
      if (redisClient) {
        await new Promise(res => setTimeout(res, 1000));
        const exists = await redisClient.get(`api:users:reset-password:${resetCode}`);
        expect(exists).toBeFalsy();
      }
    });
  });

  describe('POST /auth/password/expired', () => {
    it('should fail with missing params', async () => {
      const res = await request(app).post('/api/v1/auth/password/expired').send({});
      expect(res.status).toBe(400);
    });

    it('should update expired password and send confirmation email (simulate)', async () => {
      // Simule un mot de passe expiré pour le test user
      const userRepo = AppDataSource.getRepository('User');
      await userRepo.update({ email: testEmail }, { passwordStatus: 'EXPIRED', passwordUpdatedAt: new Date('2000-01-01') });

      const newPassword = 'ExpiredPwd1!';
      const res = await request(app)
        .post('/api/v1/auth/password/expired')
        .send({ email: testEmail, password: 'NewTestPwd1!', newPassword });
      expect(res.status).toBe(200);
      currentPassword = newPassword; // <-- MAJ du mot de passe courant

      // Récupère le code de confirmation dans Redis
      if (redisClient) {
        const keys = await redisClient.keys('api:users:confirm-password:*');
        expect(keys.length).toBeGreaterThan(0);
        confirmCode = keys[0].split(':').pop()!;
        const userId = await redisClient.get(keys[0]);
        expect(userId).toBeTruthy();
      }
    });
  });

  describe('POST /auth/password/:code/confirm', () => {
    it('should fail with invalid code', async () => {
      const res = await request(app)
        .post('/api/v1/auth/password/invalidcode/confirm');
      expect(res.status).toBe(400);
    });

    it('should confirm password change with code', async () => {
      const res = await request(app)
        .post(`/api/v1/auth/password/${confirmCode}/confirm`);
      expect(res.status).toBe(200);
      expect(res.body.data.message).toMatch(/Password confirmed/i);

      // Vérifie que le code a été supprimé de Redis
      if (redisClient) {
        await new Promise(res => setTimeout(res, 100));
        const exists = await redisClient.get(`api:users:confirm-password:${confirmCode}`);
        expect(exists).toBeFalsy();
      }
    });
  });

  describe('POST /auth/token/refresh', () => {
    it('should fail to refresh token without auth', async () => {
      const res = await request(app)
        .post('/api/v1/auth/token/refresh');
      expect(res.status).toBe(401);
    });

    it('should refresh token with valid user', async () => {
      // Effectue un login juste avant pour garantir un token valide
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testEmail, password: currentPassword }); // <-- utilise le mot de passe courant
      expect(loginRes.status).toBe(200);
      const freshToken = loginRes.body.data.token;
      expect(freshToken).toBeTruthy();

      const res = await request(app)
        .post('/api/v1/auth/token/refresh')
        .set('Authorization', `Bearer ${freshToken}`);
      expect(res.status).toBe(200);
      expect(res.body.data.token).toBeTruthy();
    });
  });
});
