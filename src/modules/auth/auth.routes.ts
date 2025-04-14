import { BaseRouter } from '@/common/routing/BaseRouter';
import { Request, Response, NextFunction } from '@/common/http';
import { Post, Delete, authorize } from '@/common/routing/decorators';
import { UnauthorizedError } from '@/common/errors/httpErrors';
import { SecurityLevel } from '@/modules/users/models/users.types';
import { AuthService } from './services/auth.services';
import { UsersService } from '../users/services/users.services';

export default class AuthRouter extends BaseRouter {
  private authService: AuthService;
  private usersService: UsersService;

  constructor() {
    super();
    this.authService = new AuthService();
    this.usersService = new UsersService();
  }

  /**
   * @api {post} /api/v1/login Connexion utilisateur
   * @apiGroup Authentication
   * @apiPermission none
   * // ... (autres tags apiDoc)
   */
  @Post('/login')
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { email, password } = req.body;
    await this.pipe(res, req, next, () => this.authService.login(email, password), 200);
  }

  /**
   * @api {delete} /api/v1/logout Déconnexion utilisateur
   * @apiGroup Authentication
   * @apiHeader {String} Authorization Bearer Token JWT.
   * @apiPermission Utilisateur authentifié (n'importe quel niveau)
   * // ... (autres tags apiDoc)
   */
  @Delete('/logout')
  @authorize({ level: SecurityLevel.READER })
  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    const token = req.user?.authToken;
    if (!token) {
      this.logger.error(
        'Logout error: Missing authToken on request after authentication middleware.',
      );
      return next(new UnauthorizedError('Logout failed due to missing token context.'));
    }

    await this.pipe(
      res,
      req,
      next,
      async () => {
        await this.authService.logout(token);
        return 'Logout successful';
      },
      200,
    );
  }

  /**
   * @api {post} /api/v1/password/:code/confirm Confirmer changement MDP
   * @apiGroup Authentication
   * @apiPermission none
   * // ... (autres tags apiDoc)
   */
  @Post('/password/:code/confirm')
  async confirmPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { code } = req.params;
    await this.pipe(
      res,
      req,
      next,
      async () => {
        await this.usersService.confirmPasswordChange(code);
        res.jsend.success('Password change confirmed successfully.');
      },
      200,
    );
  }

  /**
   * @api {post} /api/v1/generate-token Generate Token for User (Admin)
   * @apiName GenerateToken
   * @apiGroup Authentication
   * @apiVersion 1.0.0
   * @apiPermission Admin User
   *
   */
  @Post('/token/generate')
  @authorize({ level: SecurityLevel.ADMIN })
  async generateTokenForUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { userId } = req.query;

    await this.pipe(res, req, next, async () => this.authService.generateTokenForUser(userId), 200);
  }

  /**
   * @api {post} /api/v1/password/reset Demander réinitialisation MDP
   * @apiGroup Authentication
   * @apiPermission none
   * // ... (autres tags apiDoc)
   */
  @Post('/password/reset')
  async requestPasswordReset(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { email } = req.body;
    const referer = req.headers.referer || req.headers.origin;
    await this.pipe(
      res,
      req,
      next,
      async () => {
        await this.usersService.sendPasswordResetEmail(email, referer);
        res.jsend.success(
          'If your email exists in our system, a password reset link has been sent.',
        );
      },
      200,
    );
  }

  /**
   * @api {post} /api/v1/password/reset/:code/confirm Confirmer réinitialisation MDP
   * @apiGroup Authentication
   * @apiPermission none
   * // ... (autres tags apiDoc)
   */
  @Post('/password/reset/:code/confirm')
  async confirmPasswordReset(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { code } = req.params;
    const { password } = req.body;
    await this.pipe(
      res,
      req,
      next,
      async () => {
        await this.usersService.resetPasswordWithCode(code, password);
        res.jsend.success('Password has been successfully reset.');
      },
      200,
    );
  }
}
