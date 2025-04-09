import { BaseRouter } from '@/common/routing/BaseRouter';
import { UsersService } from './services/users.services';
import { Request, Response, NextFunction } from '@/common/http';
import { Delete, Get, Post } from '@/common/routing/decorators';

export default class UserRouter extends BaseRouter {
  private usersService: UsersService;
  constructor() {
    super();
    this.usersService = new UsersService();
  }

  // GET /api/v1/users/:id
  @Get('/users/:id')
  async getUserById(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.id, 10);
    // Utilise this.pipe héritée
    await this.pipe(res, req, next, () => this.usersService.findById(userId));
  }

  //GET /api/v1/users
  @Get('/users')
  async getAll(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.pipe(res, req, next, () => this.usersService.findAll());
  }

  //Post /api/v1/users
  @Post('/users')
  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    const body = req.body;
    await this.pipe(res, req, next, () => this.usersService.create(body));
  }
}
