import { BaseRouter } from '@/common/routing/BaseRouter';
import { UsersService } from './services/users.services';
import { Request, Response, NextFunction } from '@/config/http';
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
   * GET /users - Retrieve all users.
   * @param {Request} req - The incoming request.
   * @param {Response} res - The response.
   * @param {NextFunction} next - The next middleware.
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
   * GET /users/me - Retrieve the current user's information.
   * @param {Request} req - The incoming request.
   * @param {Response} res - The response.
   * @param {NextFunction} next - The next middleware.
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
   * GET /users/:id - Retrieve a user by ID.
   * @param {Request} req - The incoming request.
   * @param {Response} res - The response.
   * @param {NextFunction} next - The next middleware.
   */
  @Get('/users/:id')
  @authorize({ level: SecurityLevel.ADMIN })
  async getUserById(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.id, 10);
    await this.pipe(res, req, next, () => this.usersService.findById(userId));
  }

  /**
   * POST /users - Create a new user.
   * @param {Request} req - The incoming request.
   * @param {Response} res - The response.
   * @param {NextFunction} next - The next middleware.
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
   * PATCH /users/:id - Update a user.
   * @param {Request} req - The incoming request.
   * @param {Response} res - The response.
   * @param {NextFunction} next - The next middleware.
   */
  @Put('/users/:id')
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
   * DELETE /users/:id - Delete a user.
   * @param {Request} req - The incoming request.
   * @param {Response} res - The response.
   * @param {NextFunction} next - The next middleware.
   */
  @Delete('/users/:id')
  @authorize({ level: SecurityLevel.ADMIN })
  async deleteUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userIdToDelete = parseInt(req.params.id, 10);
    if (req.user?.id === userIdToDelete) {
      return next(new ForbiddenError('Deleting your own account via the API is not permitted.'));
    }
    await this.pipe(
      res,
      req,
      next,
      async () => {
        this.usersService.delete(userIdToDelete);
        return 'Successfull deletion';
      },
      200,
    );
  }
}
