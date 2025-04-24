import { BaseRouter } from '@/common/routing/BaseRouter';
import { LoginService } from './services/login.services';
import { Request, Response, NextFunction } from '@/config/http';
import { Post, authorize, internal } from '@/common/routing/decorators';
import { UnauthorizedError } from '@/common/errors/httpErrors';
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
  @authorize({level: SecurityLevel.USER})
  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    const token = req.user?.authToken;
    if (!token) {
      return next(new UnauthorizedError('No authentication token provided'));
    }

    await this.pipe(res, req, next, async () => {
      this.LoginService.logout(token);
      return { message: 'Logout successful' };
    },200);
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
      await this.PasswordService.sendPasswordResetEmail(email, referer, language);
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
      this.PasswordService.resetPasswordWithCode(code, password);
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
      this.PasswordService.confirmPasswordChange(code);
      return { message: 'Password confirmed successfully' };
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
  async updateExpiredPasswordFull(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { email, newPassword, password } = req.body;
    const referer = req.headers.referer;

    if (!email) return res.jsend.fail('Parameter email not found');
    if (!password) return res.jsend.fail('Parameter password not found');
    if (!newPassword) return res.jsend.fail('Parameter newPassword not found');

    try {
      // Tente de login, si le mot de passe est expiré, une erreur sera levée
      await this.LoginService.login(email, password);
      // Si pas d'erreur, le mot de passe n'est pas expiré, donc refuse la demande
      return res.jsend.fail('Password is not expired');
    } catch (err: any) {
      if (err.code === 'ERR_PWD_EXPIRED') {
        // Mot de passe expiré, on lance la procédure de changement
        return this.pipe(res, req, next, async () =>
          this.PasswordService.updateExpiredPassword({
            email: email,
            password: newPassword,
            referer: referer,
          })
        );
      }
      // Autre erreur d'authentification
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

    await this.pipe(res, req, next, () => this.LoginService.generateTokenForUser(userId), 200);
  }
}
