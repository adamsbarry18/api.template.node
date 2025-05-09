import { BaseRouter } from '@/common/routing/BaseRouter';
import { Get, Post, Put, Delete, authorize } from '@/common/routing/decorators';
import { Request, Response, NextFunction } from '@/config/http';

import { AuthorizationService } from '../auth/services/authorization.service';
import { SecurityLevel } from '../users/models/users.entity';

export default class AuthorizationRouter extends BaseRouter {
  authorizationService = AuthorizationService.getInstance();

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
    await this.pipe(res, req, next, () => this.authorizationService.getAllFeatures());
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
    await this.pipe(res, req, next, () => this.authorizationService.listAuthorisationsByLevel());
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
      this.authorizationService.listAuthorisationsFromLevel(level),
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
    await this.pipe(res, req, next, () => this.authorizationService.getAuthorisation(userId));
  }

  /**
   * @openapi
   * /authorization/users/{userId}/status:
   *   post:
   *     summary: Update user status (active, expiration, level)
   *     description: Allows an administrator to activate/deactivate a user, set or remove their permission expiration date, and optionally change their security level.
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
   *                 nullable: true
   *                 description: The date and time when the user's permissions expire. Set to null to remove expiration.
   *               level:
   *                 type: integer
   *                 description: Optional new security level for the user.
   *               isActive:
   *                 type: boolean
   *                 description: Set to true to activate the user, false to deactivate.
   *     responses:
   *       200:
   *         description: User status updated successfully
   *       404:
   *         description: User not found
   */
  @Post('/authorization/users/:userId/status')
  @authorize({ level: SecurityLevel.ADMIN })
  async updateUserStatus(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.userId, 10);
    const { expire, level, isActive } = req.body;

    let expireDate: Date | null | undefined = undefined;
    if (expire === null) {
      expireDate = null;
    } else if (expire) {
      expireDate = new Date(expire);
    }

    await this.pipe(res, req, next, () =>
      this.authorizationService.updateUserStatus(userId, {
        expire: expireDate,
        level: level !== undefined ? parseInt(level, 10) : undefined,
        isActive: isActive,
      }),
    );
  }

  /**
   * @openapi
   * /authorization/users/{userId}:
   *   put:
   *     summary: Update user authorization details (level, permissions, status, expiration)
   *     description: Allows comprehensive update of a user's authorization settings including their security level, specific permission overrides, active status, and permission expiration date.
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
   *                 description: Optional new security level for the user.
   *               permissions:
   *                 type: object
   *                 nullable: true
   *                 description: Optional specific permission overrides. Maps feature names to arrays of allowed action names. Set to null to remove all overrides.
   *                 example:
   *                   user: ['read', 'write']
   *                   config: ['read']
   *               isActive:
   *                 type: boolean
   *                 description: Optional. Set to true to activate the user, false to deactivate.
   *               permissionsExpireAt:
   *                 type: string
   *                 format: date-time
   *                 nullable: true
   *                 description: Optional. The date and time when the user's permissions expire. Set to null to remove expiration.
   *     responses:
   *       200:
   *         description: Authorization updated successfully
   *       404:
   *         description: User not found
   */
  @Put('/authorization/users/:userId')
  @authorize({ level: SecurityLevel.ADMIN })
  async updateAuthorization(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.userId, 10);
    const { level, permissions, isActive, permissionsExpireAt } = req.body;

    let expireDate: Date | null | undefined = undefined;
    if (permissionsExpireAt === null) {
      expireDate = null;
    } else if (permissionsExpireAt) {
      expireDate = new Date(permissionsExpireAt);
    }

    await this.pipe(res, req, next, () =>
      this.authorizationService.updateAuthorization(userId, {
        level: level !== undefined ? parseInt(level, 10) : undefined,
        permissions,
        isActive: isActive,
        permissionsExpireAt: expireDate,
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
      this.authorizationService.deleteAuthorisationsUser(userId),
    );
  }
}
