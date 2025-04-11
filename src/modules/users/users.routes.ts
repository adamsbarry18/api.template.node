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
// Importez SecurityLevel et CrudAction si vous utilisez les permissions par feature/action
import { SecurityLevel, Action } from './models/users.types'; // Ajustez chemin

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
  @paginate() // Active pagination, tri, etc. via middlewares (si configuré)
  @sortable(['id', 'email', 'name', 'surname', 'createdAt']) // Champs triables autorisés
  @filterable(['level', 'internal', 'email']) // Champs filtrables autorisés (ex: ?level=2&internal=true)
  @searchable(['email', 'name', 'surname']) // Champs pour recherche textuelle (ex: ?search=john)
  async getAllUsers(req: Request, res: Response, next: NextFunction): Promise<void> {
    // Le service peut utiliser req.user pour filtrer les internes si l'appelant n'est pas interne
    // mais ici, on demande niveau ADMIN, donc l'appelant est forcément interne ou admin.
    await this.pipe(res, req, next, () =>
      this.usersService.findAll({ requestingUser: req.user /* pagination, etc. from req */ }),
    );
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
  @authorize({ level: SecurityLevel.ADMIN }) // Seul un admin peut voir un autre utilisateur par ID
  // Alternative Feature/Action: @authorize({ feature: 'user', action: CrudAction.READ }) // Si 'READ' permet de voir n'importe qui
  async getUserById(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = parseInt(req.params.id, 10);
    // Ajouter une vérification pour empêcher de voir un user interne si l'appelant ne l'est pas ?
    // Pourrait être fait dans le service findById ou ici. Mais avec level:ADMIN, c'est moins critique.
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
  @authorize({ level: SecurityLevel.ADMIN }) // Seul un admin peut créer un utilisateur
  // @authorize({ feature: 'user', action: Action.CREATE })
  async createUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userInput = req.body;
    await this.pipe(
      res,
      req,
      next,
      () => this.usersService.create(userInput, { requestingUser: req.user }),
      201,
    ); // 201 Created
  }

  /**
   * @api {patch} /api/v1/users/:id Mettre à jour un utilisateur (partiel)
   * @apiGroup Users
   * @apiHeader {String} Authorization Bearer Token JWT.
   * @apiPermission Utilisateur modifiant ses propres informations OU Admin
   * // ... (autres tags apiDoc)
   */
  @Patch('/users/:id') // PATCH pour mise à jour partielle
  // On applique un niveau de base requis pour *tenter* une mise à jour
  @authorize({ level: SecurityLevel.USER }) // Au minimum, il faut être un 'USER' pour modifier (même soi-même)
  // Alternative Feature/Action: @authorize({ feature: 'user', action: CrudAction.UPDATE })
  async updateUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userIdToUpdate = parseInt(req.params.id, 10);
    const updateData = req.body;
    const requestingUser = req.user;

    // --- Logique d'autorisation fine DANS le handler ---
    // Vérifier si l'utilisateur met à jour son propre profil OU s'il est Admin
    if (requestingUser?.id !== userIdToUpdate && requestingUser?.level < SecurityLevel.ADMIN) {
      // L'utilisateur n'est pas admin ET n'essaie pas de se modifier lui-même
      return next(new ForbiddenError('You do not have permission to update this user.'));
    }
    // Si l'utilisateur est admin ou met à jour son propre profil, on continue
    // Le service pourrait avoir une logique supplémentaire pour empêcher l'auto-modification de 'level' ou 'internal'

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
  @authorize({ level: SecurityLevel.ADMIN }) // Seul un admin peut supprimer
  // Alternative Feature/Action: @authorize({ feature: 'user', action: CrudAction.DELETE })
  async deleteUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const userIdToDelete = parseInt(req.params.id, 10);

    // Sécurité additionnelle: Empêcher un admin de se supprimer lui-même via l'API ?
    if (req.user?.id === userIdToDelete) {
      return next(new ForbiddenError('Deleting your own account via the API is not permitted.'));
    }

    await this.pipe(res, req, next, () => this.usersService.delete(userIdToDelete), 204); // 204 No Content
  }
}
