import request from 'supertest';
import { describe, it, expect, beforeAll } from 'vitest';

import app from '@/app';
import { appDataSource } from '@/database/data-source';
import { redisClient } from '@/lib/redis';
import { User } from '@/modules/users/models/users.entity';

import { PasswordService } from '../services/password.services';

import { adminToken } from '@/tests/globalSetup';
const passwordService = PasswordService.getInstance();

const testEmail = 'user.test2@example.com';
let currentPassword = 'Password123!';

let resetCode: string;
let confirmCode: string;
// let userToken: string; // Removed unused variable

let testUserId: number;

describe('Auth API', () => {
  beforeAll(async () => {
    if (redisClient) {
      const keys = await redisClient.keys('api:users:*');
      for (const key of keys) {
        await redisClient.del(key);
      }
    }

    const initialPassword = 'Password123!';
    const userRepo = appDataSource.getRepository(User);
    const hashedPassword = await passwordService.hashPassword(initialPassword);
    await userRepo.update({ email: testEmail }, { password: hashedPassword });
    currentPassword = initialPassword;

    const testUser = await userRepo.findOneBy({ email: testEmail });
    if (!testUser) throw new Error('Test user not found after initial setup');
    testUserId = testUser.id;
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: testEmail, password: currentPassword });
    if (loginRes.status !== 200 || !loginRes.body.data.token) {
      throw new Error('Failed to login test user during initial setup');
    }
    // userToken = loginRes.body.data.token; // Removed assignment to unused variable
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
      // userToken = res.body.data.token; // Removed assignment to unused variable
    });

    it('should fail to login if user is inactive', async () => {
      // Ensure user is inactive for this test
      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ isActive: false });

      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testEmail, password: currentPassword });
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Unauthorized');
      expect(res.body.data).toBe('Account is inactive.');

      // Reactivate user for subsequent tests
      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ isActive: true });
    });

    it('should fail to login if user permissions have expired', async () => {
      const pastDate = new Date(Date.now() - 86400000).toISOString(); // 1 day ago
      // Ensure user permissions are expired
      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ permissionsExpireAt: pastDate });

      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testEmail, password: currentPassword });
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Unauthorized');
      expect(res.body.data).toBe('Account permissions have expired.');

      // Remove expiration for subsequent tests
      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ permissionsExpireAt: null });
    });

    it('should login successfully if user permissions have not expired', async () => {
      const futureDate = new Date(Date.now() + 86400000).toISOString(); // 1 day in future
      // Ensure user permissions are not expired
      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ permissionsExpireAt: futureDate });

      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testEmail, password: currentPassword });
      expect(res.status).toBe(200);
      expect(res.body.data.token).toBeTruthy();

      // Remove expiration for subsequent tests
      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ permissionsExpireAt: null });
    });
  });

  describe('POST /auth/logout', () => {
    it('should fail without token', async () => {
      const res = await request(app).post('/api/v1/auth/logout');
      expect(res.status).toBe(401);
    });

    it('should logout successfully', async () => {
      // Ensure user is active before logging in to get the token for logout test
      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ isActive: true });

      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testEmail, password: currentPassword });
      // Add a check here to ensure login was successful before proceeding
      if (loginRes.status !== 200 || !loginRes.body.data.token) {
        throw new Error(
          `Login failed before logout test. Status: ${loginRes.status}, Body: ${JSON.stringify(loginRes.body)}`,
        );
      }
      const tokenForLogout = loginRes.body.data.token;

      const res = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${tokenForLogout}`);
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

      if (redisClient) {
        const keys = await redisClient.keys('api:users:reset-password:*');
        expect(keys.length).toBeGreaterThan(0);
        const extractedCode = keys[0].split(':').pop();
        if (!extractedCode) {
          throw new Error(`Could not extract reset code from Redis key: ${keys[0]}`);
        }
        resetCode = extractedCode;
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
      currentPassword = newPassword;

      if (redisClient) {
        await new Promise((res) => setTimeout(res, 100));
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
      const userRepo = appDataSource.getRepository('User');
      await userRepo.update(
        { email: testEmail },
        { passwordStatus: 'EXPIRED', passwordUpdatedAt: new Date('2000-01-01') },
      );

      const oldPassword = currentPassword;
      const newPassword = 'ExpiredPwd1!';
      const res = await request(app)
        .post('/api/v1/auth/password/expired')
        .send({ email: testEmail, password: oldPassword, newPassword });
      expect(res.status).toBe(200);
      currentPassword = newPassword;

      if (redisClient) {
        const keys = await redisClient.keys('api:users:confirm-password:*');
        expect(keys.length).toBeGreaterThan(0);
        const extractedConfirmCode = keys[0].split(':').pop();
        if (!extractedConfirmCode) {
          throw new Error(`Could not extract confirmation code from Redis key: ${keys[0]}`);
        }
        confirmCode = extractedConfirmCode;
        const userId = await redisClient.get(keys[0]);
        expect(userId).toBeTruthy();
      }
    });
  });

  describe('POST /auth/password/:code/confirm', () => {
    it('should fail with invalid code', async () => {
      const res = await request(app).post('/api/v1/auth/password/invalidcode/confirm');
      expect(res.status).toBe(400);
    });

    it('should confirm password change with code', async () => {
      const res = await request(app).post(`/api/v1/auth/password/${confirmCode}/confirm`);
      expect(res.status).toBe(200);
      expect(res.body.data.message).toMatch(/Password confirmed/i);

      if (redisClient) {
        await new Promise((res) => setTimeout(res, 100));
        const exists = await redisClient.get(`api:users:confirm-password:${confirmCode}`);
        expect(exists).toBeFalsy();
      }
    });
  });
  /*
  describe('POST /auth/token/refresh', () => {
    it('should fail to refresh token without auth', async () => {
      const res = await request(app).post('/api/v1/auth/token/refresh');
      expect(res.status).toBe(401);
    });

    it('should refresh token with valid user', async () => {
      // Ensure user is active before logging in to get the token for refresh test
      await request(app)
        .put(`/api/v1/authorization/users/${testUserId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ isActive: true });

      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testEmail, password: currentPassword });
      // Add a check here to ensure login was successful before proceeding
      if (loginRes.status !== 200 || !loginRes.body.data.token) {
        throw new Error(
          `Login failed before refresh token test. Status: ${loginRes.status}, Body: ${JSON.stringify(loginRes.body)}`,
        );
      }
      const freshToken = loginRes.body.data.token;
      expect(freshToken).toBeTruthy();

      const res = await request(app)
        .post('/api/v1/auth/token/refresh')
        .set('Authorization', `Bearer ${freshToken}`);
      expect(res.status).toBe(200);
      expect(res.body.data.token).toBeTruthy();
    });
  });*/
});

describe('PUT /users/:userId/password', () => {
  let currentTokenForPutTests: string;

  beforeEach(async () => {
    // Reset user 2 state before getting token
    await request(app)
      .put(`/api/v1/authorization/users/${testUserId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ isActive: true, permissionsExpireAt: null });

    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: testEmail, password: currentPassword });
    currentTokenForPutTests = loginRes.body.data.token;
  });

  it('should fail without authentication token', async () => {
    const res = await request(app)
      .put(`/api/v1/users/${testUserId}/password`)
      .send({ password: 'NewPassword123!' });
    expect(res.status).toBe(401);
  });

  it('should fail with invalid userId format', async () => {
    const res = await request(app)
      .put('/api/v1/users/invalid-id/password')
      .set('Authorization', `Bearer ${currentTokenForPutTests}`)
      .send({ password: 'NewPassword123!' });
    expect(res.status).toBe(400);
  });

  it('should fail with missing password', async () => {
    const res = await request(app)
      .put(`/api/v1/users/${testUserId}/password`)
      .set('Authorization', `Bearer ${currentTokenForPutTests}`)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/Missing or invalid required parameter: password/i);
  });

  it('should fail with password identical to the current one', async () => {
    const res = await request(app)
      .put(`/api/v1/users/${testUserId}/password`)
      .set('Authorization', `Bearer ${currentTokenForPutTests}`)
      .send({ password: currentPassword });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('Bad request');
    expect(res.body.data).toMatch(/New password must be different/i);
  });

  it('should fail with password not meeting complexity requirements', async () => {
    const res = await request(app)
      .put(`/api/v1/users/${testUserId}/password`)
      .set('Authorization', `Bearer ${currentTokenForPutTests}`)
      .send({ password: 'weak' });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('Bad request');
    expect(res.body.data).toMatch(/Password security is too low/i);
  });

  it('should successfully update own password directly (no confirmation needed)', async () => {
    const newPasswordForSelf = 'MyNewSecurePwd1!';
    const res = await request(app)
      .put(`/api/v1/users/${testUserId}/password`)
      .set('Authorization', `Bearer ${currentTokenForPutTests}`)
      .send({ password: newPasswordForSelf });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data).toBe(true);

    currentPassword = newPasswordForSelf;

    const loginResAfterUpdate = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: testEmail, password: currentPassword });
    expect(
      loginResAfterUpdate.status,
      'Failed to login with new password immediately after update',
    ).toBe(200);
    expect(loginResAfterUpdate.body.data.token).toBeTruthy();
  });

  it('should fail to update another user password without specific rights', async () => {
    const otherUserId = 1;
    expect(otherUserId).not.toBe(testUserId);

    const res = await request(app)
      .put(`/api/v1/users/${otherUserId}/password`)
      .set('Authorization', `Bearer ${currentTokenForPutTests}`)
      .send({ password: 'AnotherPassword1!' });
    expect(res.status).toBe(403);
    expect(res.body.message).toBe('Forbidden');
    expect(res.body.data).toMatch(/Insufficient permissions|cannot update password for user/i);
  });

  it('should allow admin to update another user password', async () => {
    const newPasswordByAdmin = 'AdminSetSecurePwd1!';
    const res = await request(app)
      .put(`/api/v1/users/${testUserId}/password`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ password: newPasswordByAdmin });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data).toBe(true);
    currentPassword = newPasswordByAdmin;

    const loginAfterAdminUpdate = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: testEmail, password: currentPassword });
    expect(
      loginAfterAdminUpdate.status,
      'Login with new password set by admin failed immediately after update',
    ).toBe(200);
  });
});
