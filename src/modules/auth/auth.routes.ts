import { BaseRouter } from '@/common/routing/BaseRouter';
import { Request, Response, NextFunction } from '@/common/http';
import { Post, Delete, validate, authorize } from '@/common/routing/decorators';
import { UnauthorizedError } from '@/common/errors/httpErrors';
import { AuthService } from './services/auth.services';
import { UsersService } from '../users/services/users.services';
import { SecurityLevel } from '../users/models/users.types';

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
  // PAS de @authorize() ici - route publique
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.pipe(
      res,
      req,
      next,
      () => this.authService.login(req.body.email, req.body.password),
      200,
    );
  }

  /**
   * @api {delete} /api/v1/logout Déconnexion utilisateur
   * @apiGroup Authentication
   * @apiHeader {String} Authorization Bearer Token JWT.
   * @apiPermission Utilisateur authentifié (n'importe quel niveau)
   * // ... (autres tags apiDoc)
   */
  @Delete('/logout')
  // @authorize({ level: SecurityLevel.EXTERNAL }) // Requiert juste d'être authentifié (level 0 ou plus)
  // @authorize({ level: SecurityLevel.READER })
  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    const authHeader = req.headers.authorization;
    let token: string | null = null;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
    if (!token) {
      // Normalement géré par requireAuth déclenché par @authorize, mais double sécurité.
      return next(
        new UnauthorizedError('Bearer token missing or malformed in Authorization header.'),
      );
    }
    await this.pipe(res, req, next, () => this.authService.logout(token), 204);
  }

  /**
   * @api {post} /api/v1/password/:code/confirm Confirmer changement MDP
   * @apiGroup Authentication
   * @apiPermission none
   * // ... (autres tags apiDoc)
   */
  @Post('/password/:code/confirm')
  // PAS de @authorize() ici - route publique (sécurisée par le code unique)
  async confirmPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.pipe(
      res,
      req,
      next,
      () => this.usersService.confirmPasswordChange(req.params.code),
      200,
    );
  }

  /**
   * @api {post} /api/v1/password/reset Demander réinitialisation MDP
   * @apiGroup Authentication
   * @apiPermission none
   * // ... (autres tags apiDoc)
   */
  @Post('/password/reset')
  // PAS de @authorize() ici - route publique
  async requestPasswordReset(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.pipe(
      res,
      req,
      next,
      async () => {
        await this.usersService.sendPasswordResetEmail(req.body.email, req.headers.referer);
        return {
          message: 'If your email exists in our system, a password reset link has been sent.',
        };
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
  // PAS de @authorize() ici - route publique (sécurisée par le code unique)
  async confirmPasswordReset(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.pipe(
      res,
      req,
      next,
      () => this.usersService.resetPasswordWithCode(req.params.code, req.body.password),
      200,
    );
  }
}
