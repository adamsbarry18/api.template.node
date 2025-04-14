// src/modules/users/user.router.ts

import { BaseRouter } from '@/common/routing/BaseRouter';
import { UsersService } from './services/users.services';
import { Request, Response, NextFunction } from '@/common/http';
import {
  Get,
  Post,
  Put,
  Patch,
  Delete,
  validate,
  authorize,
  paginate,
  sortable,
  filterable,
  searchable,
} from '@/common/routing/decorators';
import { ForbiddenError, UnauthorizedError } from '@/common/errors/httpErrors';
import { SecurityLevel, Action } from './models/users.types';

export default class UserRouter extends BaseRouter {
  private usersService: UsersService;

  constructor() {
    super();
    this.usersService = new UsersService();
  }

  /**
   * @api {get} /api/v1/users Récupérer la liste des utilisateurs
   * @apiGroup Users
   * @apiHeader {String} Authorization Bearer Token JWT.
   * @apiPermission Admin requis
   * // ... (autres tags apiDoc)
   */
  @Get('/users')
  @authorize({ level: SecurityLevel.ADMIN }) // Seuls les admins peuvent lister tous les utilisateurs
  // Alternative Feature/Action: @authorize({ feature: 'user', action: CrudAction.READ }) // Si 'READ' sur 'user' signifie lister tous
  @paginate()
  @sortable(['id', 'email', 'name', 'surname', 'createdAt'])
  @filterable(['level', 'internal', 'email'])
  @searchable(['email', 'name', 'surname'])
  async getAllUsers(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.pipe(res, req, next, () => this.usersService.findAll({ requestingUser: req.user }));
  }

  /**
   * @api {get} /api/v1/users/me Récupérer l'utilisateur connecté
   * @apiGroup Users
   * @apiHeader {String} Authorization Bearer Token JWT.
   * @apiPermission Utilisateur connecté (Reader ou plus)
   * // ... (autres tags apiDoc)
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
   * @api {get} /api/v1/users/:id Récupérer un utilisateur par ID
   * @apiGroup Users
   * @apiHeader {String} Authorization Bearer Token JWT.
   * @apiPermission Admin requis
   * // ... (autres tags apiDoc)
   */
  @Get('/users/:id')
  @authorize({ level: SecurityLevel.ADMIN })
  async getUserById(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.id, 10);
    await this.pipe(res, req, next, () => this.usersService.findById(userId));
  }

  /**
   * @api {post} /api/v1/users Créer un nouvel utilisateur
   * @apiGroup Users
   * @apiHeader {String} Authorization Bearer Token JWT.
   * @apiPermission Admin requis
   * // ... (autres tags apiDoc)
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
   * @api {patch} /api/v1/users/:id Mettre à jour un utilisateur (partiel)
   * @apiGroup Users
   * @apiHeader {String} Authorization Bearer Token JWT.
   * @apiPermission Utilisateur modifiant ses propres informations OU Admin
   * // ... (autres tags apiDoc)
   */
  @Patch('/users/:id')
  @authorize({ level: SecurityLevel.USER })
  async updateUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userIdToUpdate = parseInt(req.params.id, 10);
    const updateData = req.body;
    const requestingUser = req.user;
    if (requestingUser?.id !== userIdToUpdate && requestingUser?.level < SecurityLevel.ADMIN) {
      return next(new ForbiddenError('You do not have permission to update this user.'));
    }
    await this.pipe(res, req, next, () =>
      this.usersService.update(userIdToUpdate, updateData, { requestingUser }),
    );
  }

  /**
   * @api {delete} /api/v1/users/:id Supprimer un utilisateur
   * @apiGroup Users
   * @apiHeader {String} Authorization Bearer Token JWT.
   * @apiPermission Admin requis
   * // ... (autres tags apiDoc)
   */
  @Delete('/users/:id')
  @authorize({ level: SecurityLevel.ADMIN })
  async deleteUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userIdToDelete = parseInt(req.params.id, 10);
    if (req.user?.id === userIdToDelete) {
      return next(new ForbiddenError('Deleting your own account via the API is not permitted.'));
    }

    await this.pipe(res, req, next, () => this.usersService.delete(userIdToDelete), 204);
  }
}
