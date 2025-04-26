import { ForbiddenError, UnauthorizedError } from '@/common/errors/httpErrors';
import { BaseRouter } from '@/common/routing/BaseRouter';
import {
  Get,
  Post,
  Put,
  Delete,
  authorize,
  paginate,
  sortable,
  filterable,
  searchable,
} from '@/common/routing/decorators';
import { Request, Response, NextFunction } from '@/config/http';

import { SecurityLevel, User } from './models/users.entity';
import { UsersService } from './services/users.services';

export default class UserRouter extends BaseRouter {
  usersService = UsersService.getInstance();

  /**
   * @openapi
   * /users:
   *   get:
   *     summary: Get all users
   *     tags:
   *       - Users
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: query
   *         name: page
   *         schema:
   *           type: integer
   *         description: Page number for pagination
   *       - in: query
   *         name: limit
   *         schema:
   *           type: integer
   *         description: Number of items per page
   *     responses:
   *       200:
   *         description: List of users
   */
  @Get('/users')
  @authorize({ level: SecurityLevel.ADMIN })
  @paginate()
  @sortable(['id', 'email', 'name', 'surname', 'createdAt'])
  @filterable(['level', 'internal', 'email'])
  @searchable(['email', 'name', 'surname'])
  async getAllUsers(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.pipe(res, req, next, () => this.usersService.findAll({ requestingUser: req.user }));
  }

  /**
   * @openapi
   * /users/me:
   *   get:
   *     summary: Get current user information
   *     tags:
   *       - Users
   *     security:
   *       - bearerAuth: []
   *     responses:
   *       200:
   *         description: Current user information
   *       401:
   *         description: Unauthorized
   */
  @Get('/users/me')
  @authorize({ level: SecurityLevel.READER })
  async getCurrentUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = req.user?.id;
    if (!userId) {
      return next(new UnauthorizedError('User ID not found in token payload.'));
    }
    await this.pipe(res, req, next, () => this.usersService.findById(userId));
  }

  /**
   * @openapi
   * /users/{id}:
   *   get:
   *     summary: Get user by ID
   *     tags:
   *       - Users
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *         description: User ID
   *     responses:
   *       200:
   *         description: User found
   *       404:
   *         description: User not found
   */
  /**
   * @openapi
   * /users/{identifier}:
   *   get:
   *     summary: Get user by ID or email
   *     tags:
   *       - Users
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: identifier
   *         required: true
   *         schema:
   *           type: string
   *         description: User ID (numeric) or email address
   *     responses:
   *       200:
   *         description: User found
   *       403:
   *         description: Forbidden (Insufficient permissions)
   *       404:
   *         description: User not found
   */
  @Get('/users/:identifier')
  @authorize({ level: SecurityLevel.USER })
  async getUserByIdentifier(req: Request, res: Response, next: NextFunction): Promise<void> {
    const identifier = req.params.identifier;

    if (identifier.includes('@')) {
      const userEmail = identifier;
      await this.pipe(res, req, next, () => this.usersService.findByEmail(userEmail));
    } else {
      const userId = parseInt(identifier, 10);
      if (isNaN(userId)) {
        return next(
          new ForbiddenError(
            `Invalid identifier: ${identifier}. Must be a numeric ID or an email.`,
          ),
        );
      }
      await this.pipe(res, req, next, () => this.usersService.findById(userId));
    }
  }

  /**
   * @openapi
   * /users:
   *   post:
   *     summary: Create a new user
   *     tags:
   *       - Users
   *     security:
   *       - bearerAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/UserInput'
   *     responses:
   *       201:
   *         description: User created
   *       400:
   *         description: Invalid data
   */
  @Post('/users')
  @authorize({ level: SecurityLevel.ADMIN })
  async createUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userInput = req.body;
    await this.pipe(
      res,
      req,
      next,
      () => this.usersService.create(userInput, { requestingUser: req.user }),
      201,
    );
  }

  /**
   * @openapi
   * /users/{id}:
   *   put:
   *     summary: Update a user
   *     tags:
   *       - Users
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *         description: User ID
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/UserInput'
   *     responses:
   *       200:
   *         description: User updated
   *       403:
   *         description: Forbidden
   *       404:
   *         description: User not found
   */
  @Put('/users/:id')
  @authorize({ level: SecurityLevel.READER })
  async updateUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userIdToUpdate = parseInt(req.params.id, 10);
    const updateData = req.body;

    if (req.user?.id !== userIdToUpdate && (req.user?.level ?? -1) < SecurityLevel.ADMIN) {
      return next(new ForbiddenError('You can only update your own account'));
    }
    await this.pipe(res, req, next, () =>
      this.usersService.update(userIdToUpdate, updateData, { requestingUser: req.user }),
    );
  }

  /**
   * @openapi
   * /users/{id}:
   *   delete:
   *     summary: Delete a user
   *     tags:
   *       - Users
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *         description: User ID
   *     responses:
   *       200:
   *         description: User deleted
   *       403:
   *         description: Forbidden
   *       404:
   *         description: User not found
   */
  @Delete('/users/:id')
  @authorize({ level: SecurityLevel.READER })
  async deleteUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userIdToDelete = parseInt(req.params.id, 10);

    if (req.user?.id !== userIdToDelete && (req.user?.level ?? -1) < SecurityLevel.ADMIN) {
      return next(new ForbiddenError('You can only delete your own account'));
    }
    await this.pipe(
      res,
      req,
      next,
      async () => {
        await this.usersService.delete(userIdToDelete, { requestingUser: req.user });
        return 'Successfull deletion';
      },
      200,
    );
  }

  /**
   * @openapi
   * /users/{id}/preferences:
   *   put:
   *     summary: Update user preferences
   *     tags:
   *       - Users
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *         description: User ID
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *     responses:
   *       200:
   *         description: Preferences updated
   *       403:
   *         description: Forbidden
   *       404:
   *         description: User not found
   */
  @Put('/users/:id/preferences')
  @authorize({ level: SecurityLevel.READER })
  async updatePreferences(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.id, 10);
    const preferences = req.body;

    if (req.user?.id !== userId && (req.user?.level ?? -1) < SecurityLevel.ADMIN) {
      return next(new ForbiddenError('You can only update your own preferences'));
    }

    await this.pipe(res, req, next, () => this.usersService.updatePreferences(userId, preferences));
  }

  /**
   * @openapi
   * /users/{id}/preferences:
   *   delete:
   *     summary: Reset user preferences
   *     tags:
   *       - Users
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *         description: User ID
   *     responses:
   *       200:
   *         description: Preferences reset
   *       403:
   *         description: Forbidden
   *       404:
   *         description: User not found
   */
  @Delete('/users/:id/preferences')
  @authorize({ level: SecurityLevel.READER })
  async resetPreferences(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.id, 10);

    if (req.user?.id !== userId && (req.user?.level ?? -1) < SecurityLevel.ADMIN) {
      return next(new ForbiddenError('You can only reset your own preferences'));
    }

    await this.pipe(res, req, next, () => this.usersService.resetPreferences(userId));
  }
}
