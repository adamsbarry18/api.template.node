import { randomUUID } from 'crypto';
import { FindOptionsWhere } from 'typeorm';
import dayjs from 'dayjs';
import { UserRepository } from '../data/users.repository';
import logger from '@/lib/logger';
import {
  NotFoundError,
  BadRequestError,
  ForbiddenError,
  ServerError,
} from '@/common/errors/httpErrors';
import { Request } from '@/config/http';
import {
  CreateUserInput,
  UpdateUserInput,
  UserApiResponse,
  SecurityLevel,
  PasswordStatus,
  User,
  validationInputErrors,
} from '../models/users.entity';
import { PasswordService } from '@/modules/auth/services/password.services';
import { AuthorizationUtils } from '@/common/utils/AuthorizationUtils';

let instance: UsersService | null = null;

export class UsersService {
  private readonly userRepository: UserRepository;
  private readonly passwordService: PasswordService;

  constructor(
    userRepository: UserRepository = new UserRepository(),
    passwordService: PasswordService = new PasswordService(userRepository),
  ) {
    this.userRepository = userRepository;
    this.passwordService = passwordService;
  }

  /**
   * Convertit une entité User en objet de réponse API
   */
  mapToApiResponse(user: User | null): UserApiResponse | null {
    if (!user) return null;
    const apiUser = user.toApi() as UserApiResponse;
    if (user.createdAt) apiUser.created_time = user.createdAt;
    if (user.updatedAt) apiUser.updated_time = user.updatedAt;
    return apiUser;
  }

  /**
   * Récupère un utilisateur par son ID
   */
  async findById(
    id: number,
    options?: { requestingUser?: Request['user'] },
  ): Promise<UserApiResponse> {
    const requestingUser = options?.requestingUser;

    // Vérification des droits : seulement soi-même ou un admin peut accéder
    if (requestingUser) {
      const isSelf = requestingUser.id === id;
      const isAdmin = requestingUser.level >= SecurityLevel.ADMIN;
      if (!isSelf && !isAdmin) {
        throw new ForbiddenError('You do not have permission to access this user.');
      }
    }

    try {
      const user = await this.userRepository.findById(id);
      if (!user) throw new NotFoundError(`User with id ${id} not found.`);
      return this.mapToApiResponse(user)!;
    } catch (error) {
      if (error instanceof NotFoundError) {
        throw error;
      }
      throw new ServerError(`Error finding user with id ${id} ${error}`);
    }
  }

  /**
   * Récupère un utilisateur par son email
   */
  async findByEmail(email: string): Promise<UserApiResponse> {
    try {
      const user = await this.userRepository.findByEmail(email);
      if (!user) throw new NotFoundError(`User with email ${email} not found.`);
      return this.mapToApiResponse(user)!;
    } catch (error) {
      throw new ServerError(`Error finding user with email ${email} ${error}`);
    }
  }

  /**
   * Récupère un utilisateur par email pour l'authentification (avec mot de passe)
   */
  async findByEmailForAuth(email: string): Promise<User | null> {
    try {
      return await this.userRepository.findByEmailWithPassword(email);
    } catch (error) {
      logger.error(`Error finding user for auth with email ${email}: ${error}`);
      return null;
    }
  }

  /**
   * Récupère tous les utilisateurs, avec filtrage selon les droits du demandeur
   */
  async findAll(options?: { requestingUser?: Request['user'] }): Promise<UserApiResponse[]> {
    try {
      const where: FindOptionsWhere<User> = {};
      if (options?.requestingUser && !options.requestingUser.internal) {
        where.internal = false;
      }

      const { users } = await this.userRepository.findAll({ where });
      return users.map((user) => this.mapToApiResponse(user)!);
    } catch (error) {
      throw new ServerError(`Error finding all users ${error}`);
    }
  }

  /**
   * Crée un nouvel utilisateur ou réactive un utilisateur supprimé précédemment
   */
  async create(
    input: CreateUserInput,
    options?: { requestingUser?: Request['user'] },
  ): Promise<UserApiResponse> {
    const { password, email, permissions, permissionsExpireAt, ...restData } = input;

    // Vérification champs obligatoires
    if (!email) {
      throw new BadRequestError('Email is required.');
    }
    if (!password) {
      throw new BadRequestError('Password is required.');
    }

    const lowerCaseEmail = email.toLowerCase().trim();

    // Validation du mot de passe
    if (!this.passwordService.isPasswordValid(password)) {
      throw new BadRequestError(
        'Password does not meet complexity requirements (min. 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special character).',
      );
    }

    // Vérification des droits pour créer un utilisateur interne
    const isInternalRequestor = !!options?.requestingUser?.internal;
    if (restData.internal && !isInternalRequestor) {
      throw new ForbiddenError('Cannot create internal user without being internal.');
    }

    const existingActiveUser = await this.userRepository.findByEmail(lowerCaseEmail);
    if (existingActiveUser) {
      throw new BadRequestError('Email address is already in use by an active user.');
    }

    try {
      const hashedPassword = await this.passwordService.hashPassword(password);
      const encodedOverrides = AuthorizationUtils.encodePermissionsToString(permissions ?? {});
      const deletedUser = await this.userRepository.findDeletedByEmail(lowerCaseEmail);
      let userEntity: User;

      if (deletedUser) {
        logger.info(
          `Reactivating deleted user with email ${lowerCaseEmail} (ID: ${deletedUser.id})`,
        );

        Object.assign(deletedUser, restData);
        deletedUser.deletedAt = null;
        deletedUser.email = lowerCaseEmail;
        deletedUser.password = hashedPassword;
        deletedUser.passwordStatus = PasswordStatus.ACTIVE;
        deletedUser.passwordUpdatedAt = new Date();
        deletedUser.uid = deletedUser.uid ?? randomUUID();
        deletedUser.authorisationOverrides = encodedOverrides;
        deletedUser.permissionsExpireAt = permissionsExpireAt
          ? dayjs(permissionsExpireAt).toDate()
          : null;

        userEntity = deletedUser;
      } else {
        userEntity = this.userRepository.create({
          ...restData,
          email: lowerCaseEmail,
          password: hashedPassword,
          uid: randomUUID(),
          passwordStatus: PasswordStatus.ACTIVE,
          passwordUpdatedAt: new Date(),
          authorisationOverrides: encodedOverrides,
          permissionsExpireAt: permissionsExpireAt ? dayjs(permissionsExpireAt).toDate() : null,
        });
      }

      if (!userEntity.isValid()) {
        throw new BadRequestError(`User data is invalid ${validationInputErrors}`);
      }

      const savedUser = await this.userRepository.save(userEntity);
      logger.info(`User ${savedUser.id} ${deletedUser ? 'reactivated' : 'created'} successfully.`);

      return this.mapToApiResponse(savedUser)!;
    } catch (error: any) {
      logger.error({
        message: `Original error caught during user creation/reactivation for ${email}`,
        originalError: error,
        originalStack: error?.stack,
      });
      // Si c'est déjà une erreur http explicite, la relancer telle quelle
      if (
        error instanceof BadRequestError ||
        error instanceof ForbiddenError ||
        error instanceof NotFoundError
      ) {
        throw error;
      }
      throw new ServerError(`Failed to create user. ${error}`);
    }
  }

  /**
   * Met à jour les informations d'un utilisateur existant
   */
  async update(
    id: number,
    input: UpdateUserInput,
    options?: { requestingUser?: Request['user'] },
  ): Promise<UserApiResponse> {
    const { password, permissions, permissionsExpireAt, ...restData } = input;
    const requestingUser = options?.requestingUser;

    // Vérification des droits : seulement soi-même ou un admin peut modifier
    if (requestingUser) {
      const isSelf = requestingUser.id === id;
      const isAdmin = requestingUser.level >= SecurityLevel.ADMIN;
      if (!isSelf && !isAdmin) {
        throw new ForbiddenError('You do not have permission to update this user.');
      }
    }

    try {
      const user = await this.userRepository.findByIdWithPassword(id);
      if (!user) throw new NotFoundError(`User with id ${id} not found.`);

      const updatePayload: Partial<User> = { ...restData };
      let passwordChanged = false;

      if (password) {
        if (!this.passwordService.isPasswordValid(password)) {
          throw new BadRequestError(
            'Password does not meet complexity requirements (min. 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special character).',
          );
        }

        const isSame = await user.comparePassword(password);
        if (!isSame) {
          updatePayload.password = await this.passwordService.hashPassword(password);
          updatePayload.passwordUpdatedAt = new Date();
          updatePayload.passwordStatus = PasswordStatus.VALIDATING;
          passwordChanged = true;
        } else {
          logger.warn(`User ${id} attempted to update with the same password.`);
        }
      }

      if (permissions !== undefined) {
        updatePayload.authorisationOverrides = AuthorizationUtils.encodePermissionsToString(
          permissions ?? {},
        );
      }

      if (permissionsExpireAt !== undefined) {
        const expiryDate = permissionsExpireAt ? dayjs(permissionsExpireAt) : null;
        updatePayload.permissionsExpireAt = expiryDate?.isValid() ? expiryDate.toDate() : null;
      }

      Object.assign(user, updatePayload);

      if (!user.isValid()) {
        throw new BadRequestError(`User data after update is invalid. ${validationInputErrors}`);
      }

      const result = await this.userRepository.update(id, updatePayload);
      if (result.affected === 0) {
        throw new NotFoundError(
          `User with id ${id} not found during update (or no changes applied).`,
        );
      }

      const updatedUser = await this.userRepository.findById(id);
      if (!updatedUser) throw new ServerError('Failed to re-fetch user after update.');

      if (passwordChanged && updatedUser.passwordStatus === PasswordStatus.VALIDATING) {
        const emailLanguage = updatedUser.preferences?.language === 'fr' ? 'fr' : 'en';
        await this.passwordService.sendPasswordConfirmationEmail(updatedUser, emailLanguage);
      }

      logger.info(`User ${id} updated successfully.`);
      return this.mapToApiResponse(updatedUser)!;
    } catch (error: any) {
      logger.error(error, `Error updating user ${id}`);
      // Propager les erreurs explicites
      if (
        error instanceof BadRequestError ||
        error instanceof ForbiddenError ||
        error instanceof NotFoundError
      ) {
        throw error;
      }
      throw new ServerError(`Failed to update user ${error}`);
    }
  }

  /**
   * Met à jour les préférences d'un utilisateur
   */
  async updatePreferences(
    userId: number,
    preferences: Record<string, any> | null,
  ): Promise<UserApiResponse> {
    try {
      const result = await this.userRepository.update(userId, { preferences });
      if (result.affected === 0) throw new NotFoundError(`User with id ${userId} not found.`);

      const updatedUser = await this.userRepository.findById(userId);
      if (!updatedUser) {
        throw new ServerError('Failed to re-fetch user after preference update.');
      }

      return this.mapToApiResponse(updatedUser)!;
    } catch (error) {
      throw new ServerError(`Error updating preferences for user ${userId} ${error}`);
    }
  }

  /**
   * Réinitialise les préférences d'un utilisateur
   */
  async resetPreferences(userId: number): Promise<UserApiResponse> {
    return this.updatePreferences(userId, null);
  }

  /**
   * Suppression logique (soft delete) d'un utilisateur
   */
  async delete(id: number, options?: { requestingUser?: Request['user'] }): Promise<void> {
    const requestingUser = options?.requestingUser;

    // Vérification des droits : seulement soi-même ou un admin peut supprimer
    if (requestingUser) {
      const isSelf = requestingUser.id === id;
      const isAdmin = requestingUser.level >= SecurityLevel.ADMIN;
      if (!isSelf && !isAdmin) {
        throw new ForbiddenError('You do not have permission to delete this user.');
      }
      if (isSelf && isAdmin) {
        throw new ForbiddenError('Deleting your own account via the API is not permitted.');
      }
    }

    try {
      const user = await this.userRepository.findById(id);
      if (!user) throw new NotFoundError(`User with id ${id} not found.`);

      const anonymizedEmail = `${user.email}_deleted_${Date.now()}`;
      await this.userRepository.softDelete(id, anonymizedEmail);

      logger.info(`User ${id} successfully soft-deleted.`);
    } catch (error) {
      // Propager les erreurs explicites
      if (
        error instanceof BadRequestError ||
        error instanceof ForbiddenError ||
        error instanceof NotFoundError
      ) {
        throw error;
      }
      throw new ServerError(`Error deleting user ${id} ${error}`);
    }
  }

  static getInstance(): UsersService {
    if (!instance) {
      instance = new UsersService(new UserRepository());
    }
    return instance;
  }
}
