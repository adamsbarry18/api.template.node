import { BaseRouter } from '@/common/routing/BaseRouter';
import { AuthorizationService } from '../auth/services/authorization.service';
import { Request, Response, NextFunction } from '@/config/http';
import { Get, Post, Put, Delete, authorize } from '@/common/routing/decorators';
import { SecurityLevel } from '../users/models/users.entity';

export default class AuthorizationRouter extends BaseRouter {
  AuthorizationService = AuthorizationService.getInstance();

  /**
   * @openapi
   * /authorization/features:
   *   get:
   *     summary: Get all available features
   *     tags:
   *       - Authorization
   *     security:
   *       - bearerAuth: []
   *     responses:
   *       200:
   *         description: List of all available features and actions
   */
  @Get('/authorization/features')
  @authorize({ level: SecurityLevel.ADMIN })
  async getAllFeatures(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.pipe(res, req, next, () => this.AuthorizationService.getAllFeatures());
  }

  /**
   * @openapi
   * /authorization/levels:
   *   get:
   *     summary: Get authorisations by security level
   *     tags:
   *       - Authorization
   *     security:
   *       - bearerAuth: []
   *     responses:
   *       200:
   *         description: Authorisations mapped by security level
   */
  @Get('/authorization/levels')
  @authorize({ level: SecurityLevel.ADMIN })
  async getAuthorisationsByLevel(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.pipe(res, req, next, () => this.AuthorizationService.listAuthorisationsByLevel());
  }

  /**
   * @openapi
   * /authorization/levels/{level}:
   *   get:
   *     summary: Get authorisations for a specific security level
   *     tags:
   *       - Authorization
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: level
   *         required: true
   *         schema:
   *           type: integer
   *         description: Security level
   *     responses:
   *       200:
   *         description: Authorisations for the specified level
   */
  @Get('/authorization/levels/:level')
  @authorize({ level: SecurityLevel.ADMIN })
  async getAuthorisationsForLevel(req: Request, res: Response, next: NextFunction): Promise<void> {
    const level = parseInt(req.params.level, 10);
    await this.pipe(res, req, next, () =>
      this.AuthorizationService.listAuthorisationsFromLevel(level),
    );
  }

  /**
   * @openapi
   * /authorization/users/{userId}:
   *   get:
   *     summary: Get authorisations for a specific user
   *     tags:
   *       - Authorization
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: userId
   *         required: true
   *         schema:
   *           type: integer
   *         description: User ID
   *     responses:
   *       200:
   *         description: User's authorisations
   *       404:
   *         description: User not found
   */
  @Get('/authorization/users/:userId')
  @authorize({ level: SecurityLevel.ADMIN })
  async getUserAuthorisation(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.userId, 10);
    await this.pipe(res, req, next, () => this.AuthorizationService.getAuthorisation(userId));
  }

  /**
   * @openapi
   * /authorization/users/{userId}/temporary:
   *   post:
   *     summary: Create temporary authorization for a user
   *     tags:
   *       - Authorization
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: userId
   *         required: true
   *         schema:
   *           type: integer
   *         description: User ID
   *     requestBody:
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               expire:
   *                 type: string
   *                 format: date-time
   *               level:
   *                 type: integer
   *     responses:
   *       200:
   *         description: Temporary authorization created
   */
  @Post('/authorization/users/:userId/temporary')
  @authorize({ level: SecurityLevel.ADMIN })
  async createTemporaryAuthorization(
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> {
    const userId = parseInt(req.params.userId, 10);
    const { expire, level } = req.body;

    await this.pipe(res, req, next, () =>
      this.AuthorizationService.createTemporaryAuthorization(userId, {
        expire: expire ? new Date(expire) : undefined,
        level: level !== undefined ? parseInt(level, 10) : undefined,
      }),
    );
  }

  /**
   * @openapi
   * /authorization/users/{userId}:
   *   put:
   *     summary: Update user authorization
   *     tags:
   *       - Authorization
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: userId
   *         required: true
   *         schema:
   *           type: integer
   *         description: User ID
   *     requestBody:
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               level:
   *                 type: integer
   *               authorisationOverrides:
   *                 type: string
   *     responses:
   *       200:
   *         description: Authorization updated
   */
  @Put('/authorization/users/:userId')
  @authorize({ level: SecurityLevel.ADMIN })
  async updateAuthorization(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.userId, 10);
    const { level, authorisationOverrides } = req.body;

    await this.pipe(res, req, next, () =>
      this.AuthorizationService.updateAuthorization(userId, {
        level: level !== undefined ? parseInt(level, 10) : undefined,
        authorisationOverrides,
      }),
    );
  }

  /**
   * @openapi
   * /authorization/users/{userId}:
   *   delete:
   *     summary: Delete user's specific authorizations
   *     tags:
   *       - Authorization
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: userId
   *         required: true
   *         schema:
   *           type: integer
   *         description: User ID
   *     responses:
   *       200:
   *         description: Authorizations reset to default
   */
  @Delete('/authorization/users/:userId')
  @authorize({ level: SecurityLevel.ADMIN })
  async deleteUserAuthorizations(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.userId, 10);
    await this.pipe(res, req, next, () =>
      this.AuthorizationService.deleteAuthorisationsUser(userId),
    );
  }
}
