import { BaseRouter } from '@/common/routing/BaseRouter';
import { LoginService } from './services/login.services';
import { Request, Response, NextFunction } from '@/config/http';
import { Get, Post, Put, Delete, validate, authorize } from '@/common/routing/decorators';
import { ForbiddenError, UnauthorizedError } from '@/common/errors/httpErrors';
import { PasswordService } from './services/password.services';
import { SecurityLevel } from '../users/models/users.entity';

export default class LoginRouter extends BaseRouter {
  LoginService = LoginService.getInstance();
  PasswordService = PasswordService.getInstance();

  /**
   * @openapi
   * /auth/login:
   *   post:
   *     summary: Authenticate a user
   *     tags:
   *       - Authentication
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - email
   *               - password
   *             properties:
   *               email:
   *                 type: string
   *               password:
   *                 type: string
   *     responses:
   *       200:
   *         description: Login successful
   *       401:
   *         description: Invalid credentials
   */
  @Post('/auth/login')
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { email, password } = req.body;
    await this.pipe(res, req, next, () => this.LoginService.login(email, password));
  }

  /**
   * @openapi
   * /auth/logout:
   *   post:
   *     summary: Log out current user
   *     tags:
   *       - Authentication
   *     security:
   *       - bearerAuth: []
   *     responses:
   *       200:
   *         description: Logout successful
   */
  @Post('/auth/logout')
  @authorize({ level: SecurityLevel.READER })
  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    const token = req.user?.authToken;
    if (!token) {
      return next(new UnauthorizedError('No authentication token provided'));
    }

    await this.pipe(res, req, next, async () => {
      await this.LoginService.logout(token);
      return { message: 'Logout successful' };
    });
  }

  /**
   * @openapi
   * /auth/password/reset-request:
   *   post:
   *     summary: Request password reset
   *     tags:
   *       - Authentication
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - email
   *             properties:
   *               email:
   *                 type: string
   *               language:
   *                 type: string
   *                 enum: [fr, en]
   *                 default: en
   *     responses:
   *       200:
   *         description: Password reset email sent
   *       400:
   *         description: Invalid input
   */
  @Post('/auth/password/reset-request')
  async requestPasswordReset(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { email, language = 'en' } = req.body;

    await this.pipe(res, req, next, async () => {
      await this.PasswordService.sendPasswordResetEmail(email, language as 'fr' | 'en');
      return {
        message: 'If your email exists in our system, you will receive reset instructions shortly',
      };
    });
  }

  /**
   * @openapi
   * /auth/password/reset:
   *   post:
   *     summary: Reset password using code
   *     tags:
   *       - Authentication
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - code
   *               - newPassword
   *             properties:
   *               code:
   *                 type: string
   *               newPassword:
   *                 type: string
   *     responses:
   *       200:
   *         description: Password reset successful
   *       400:
   *         description: Invalid code or password
   */
  @Post('/auth/password/reset')
  async resetPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { code, newPassword } = req.body;

    await this.pipe(res, req, next, async () => {
      const success = await this.PasswordService.resetPasswordWithCode(code, newPassword);
      return { success, message: 'Password reset successful' };
    });
  }

  /**
   * @openapi
   * /auth/password/confirm:
   *   post:
   *     summary: Confirm password change
   *     tags:
   *       - Authentication
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - code
   *             properties:
   *               code:
   *                 type: string
   *     responses:
   *       200:
   *         description: Password confirmed
   *       400:
   *         description: Invalid code
   */
  @Post('/auth/password/confirm')
  async confirmPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { code } = req.body;

    await this.pipe(res, req, next, async () => {
      const success = await this.PasswordService.confirmPasswordChange(code);
      return { success, message: 'Password confirmed successfully' };
    });
  }

  /**
   * @openapi
   * /auth/password/expired:
   *   post:
   *     summary: Update expired password
   *     tags:
   *       - Authentication
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - email
   *               - newPassword
   *             properties:
   *               email:
   *                 type: string
   *               newPassword:
   *                 type: string
   *     responses:
   *       200:
   *         description: Password updated and new token issued
   *       400:
   *         description: Invalid input
   */
  @Post('/auth/password/expired')
  async updateExpiredPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { email, newPassword } = req.body;
    await this.pipe(res, req, next, () =>
      this.LoginService.updateExpiredPassword(email, newPassword),
    );
  }

  /**
   * @openapi
   * /auth/token/refresh:
   *   post:
   *     summary: Generate a new token for a user
   *     tags:
   *       - Authentication
   *     security:
   *       - bearerAuth: []
   *     responses:
   *       200:
   *         description: New token generated
   *       401:
   *         description: Unauthorized
   */
  @Post('/auth/token/refresh')
  @authorize({ level: SecurityLevel.READER })
  async refreshToken(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = req.user?.id;
    if (!userId) {
      return next(new UnauthorizedError('User ID not found in token payload'));
    }

    await this.pipe(res, req, next, () => this.LoginService.generateTokenForUser(userId));
  }
}
