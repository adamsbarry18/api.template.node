import { BaseRouter } from '@/common/routing/BaseRouter';
import { Request, Response, NextFunction } from '@/config/http';
import { Post, Delete, authorize } from '@/common/routing/decorators';
import { UnauthorizedError, BadRequestError } from '@/common/errors/httpErrors';
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
   * POST /login - Authenticate a user and return a token.
   * @param {Request} req The incoming request.
   * @param {Response} res The response.
   * @param {NextFunction} next The next middleware.
   */
  @Post('/login')
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { email, password } = req.body;
    await this.pipe(res, req, next, () => this.authService.login(email, password), 200);
  }

  /**
   * DELETE /logout - Logout a user by invalidating their token.
   * @param {Request} req The incoming request.
   * @param {Response} res The response.
   * @param {NextFunction} next The next middleware.
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
   * POST /password/:code/confirm - Confirm a password change.
   * @param {Request} req The incoming request.
   * @param {Response} res The response.
   * @param {NextFunction} next The next middleware.
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
   * POST /token/generate - Generate a new token for a user.
   * @param {Request} req The incoming request.
   * @param {Response} res The response.
   * @param {NextFunction} next The next middleware.
   */
  @Post('/token/generate')
  @authorize({ level: SecurityLevel.ADMIN })
  async generateTokenForUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userIdParam = req.query.userId;

    if (typeof userIdParam !== 'string' || isNaN(parseInt(userIdParam, 10))) {
      throw new BadRequestError('Invalid or missing userId query parameter.');
    }
    const userId = parseInt(userIdParam, 10);

    await this.pipe(res, req, next, async () => this.authService.generateTokenForUser(userId), 200);
  }

  /**
   * POST /password/reset - Request a password reset link.
   * @param {Request} req The incoming request.
   * @param {Response} res The response.
   * @param {NextFunction} next The next middleware.
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
        // Pass 'en' as the default language for now.
        // TODO: Consider detecting language from request headers (e.g., Accept-Language)
        await this.usersService.sendPasswordResetEmail(email, 'en', referer);
        return 'If your email exists in our system, a password reset link has been sent.';
      },
      200,
    );
  }

  /**
   * POST /password/reset/:code/confirm - Confirm a password reset.
   * @param {Request} req The incoming request.
   * @param {Response} res The response.
   * @param {NextFunction} next The next middleware.
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
