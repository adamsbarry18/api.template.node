import { Errors, UnauthorizedError } from '@/common/errors/httpErrors';
import { BaseRouter } from '@/common/routing/BaseRouter';
import { Post, Put, authorize, internal } from '@/common/routing/decorators';
import { Request, Response, NextFunction } from '@/config/http';

import { LoginService } from './services/login.services';
import { PasswordService } from './services/password.services';
import { SecurityLevel } from '../users/models/users.entity';
import { AuthorizationService } from './services/authorization.service';

export default class LoginRouter extends BaseRouter {
  loginService = LoginService.getInstance();
  passwordService = PasswordService.getInstance();
  authorizationService = AuthorizationService.getInstance();

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
    await this.pipe(res, req, next, () => this.loginService.login(email, password));
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
  @authorize({ level: SecurityLevel.USER })
  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    const token = req.user?.authToken;
    if (!token) {
      return next(new UnauthorizedError('No authentication token provided'));
    }

    await this.pipe(
      res,
      req,
      next,
      async () => {
        await this.loginService.logout(token);
        return { message: 'Logout successful' };
      },
      200,
    );
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
  @Post('/auth/password/reset')
  async requestPasswordReset(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { email, language = 'en' } = req.body;
    const referer = req.headers.referer;

    if (!email) {
      // Correction : retourne un 400 si email manquant
      return res.jsend.fail('Parameter email not found');
    }

    await this.pipe(res, req, next, async () => {
      await this.passwordService.sendPasswordResetEmail(email, referer, language);
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
  @Post('/auth/password/reset/:code/confirm')
  async resetPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { password } = req.body;
    const { code } = req.params;

    if (!code || code.length != 32) return res.jsend.fail('No confirm code');

    await this.pipe(res, req, next, async () => {
      await this.passwordService.resetPasswordWithCode(code, password);
      return { message: 'Password reset successful' };
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
   *       required: false
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               code:
   *                 type: string
   *     responses:
   *       200:
   *         description: Password confirmed
   *       400:
   *         description: Invalid code
   */
  @Post('/auth/password/:code/confirm')
  async confirmPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { code } = req.params;
    if (!code || code.length != 32) return res.jsend.fail('No confirm code');
    await this.pipe(res, req, next, async () => {
      await this.passwordService.confirmPasswordChange(code);
      return { message: 'Password confirmed successfully' };
    });
  }

  /**
   * @openapi
   * /users/{userId}/password:
   *   put:
   *     summary: Update a user's password
   *     tags:
   *       - Authentication
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: userId
   *         required: true
   *         schema:
   *           type: integer
   *         description: The ID of the user whose password is to be updated
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - password
   *             properties:
   *               password:
   *                 type: string
   *                 format: password
   *                 description: The new password for the user
   *     responses:
   *       200:
   *         description: Password updated successfully
   *       400:
   *         description: Bad Request - Missing parameters or invalid input
   *       401:
   *         description: Unauthorized - Invalid or missing authentication token
   *       403:
   *         description: Forbidden - User does not have permission to update this password
   *       404:
   *         description: Not Found - User ID not found
   */
  @Put('/users/:userId/password')
  @authorize({ level: SecurityLevel.USER })
  async updatePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { password } = req.body;
    const userId = parseInt(req.params.userId, 10);
    const referer = req.headers.referer;

    if (!password) return res.jsend.fail('Parameter password not found');
    if (!userId) return res.jsend.fail('UserId Not found');

    const isEditingSelf = req?.user?.id === parseInt(req.params.id);

    if (!isEditingSelf) {
      const authorised = await this.authorizationService.checkAuthorisation(
        userId,
        'users',
        'write',
      );
      if (!authorised) {
        throw new Errors.ForbiddenError('Cannot edit user');
      }
    }

    await this.pipe(res, req, next, async () =>
      this.passwordService.updatePassword({
        userId,
        password,
        referer,
      }),
    );
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
  async updateExpiredPasswordFull(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { email, newPassword, password } = req.body;
    const referer = req.headers.referer;

    if (!email) return res.jsend.fail('Parameter email not found');
    if (!password) return res.jsend.fail('Parameter password not found');
    if (!newPassword) return res.jsend.fail('Parameter newPassword not found');

    try {
      await this.loginService.login(email, password);
      return res.jsend.fail('Password is not expired');
    } catch (err: any) {
      if (err.code === 'ERR_PWD_EXPIRED') {
        return this.pipe(res, req, next, async () =>
          this.passwordService.updatePassword({
            email: email,
            password: newPassword,
            referer: referer,
          }),
        );
      }
      return res.status(401).jsend.fail('Authentification error');
    }
  }

  /**
   * @openapi
   * /auth/token/refresh:
   *   post:
   *     summary: Generate a new token for the currently authenticated user
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
  @internal()
  async refreshToken(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = req.user?.id ?? req.user?.sub;
    if (!userId) {
      return next(new UnauthorizedError('User ID not found in token payload'));
    }

    await this.pipe(res, req, next, () => this.loginService.generateTokenForUser(userId), 200);
  }
}
