import { randomUUID } from 'crypto';

import dayjs from 'dayjs';
import { type FindOptionsWhere } from 'typeorm';

import {
  NotFoundError,
  BadRequestError,
  ForbiddenError,
  ServerError,
} from '@/common/errors/httpErrors';
import { AuthorizationUtils } from '@/common/utils/AuthorizationUtils';
import { type Request } from '@/config/http';
import logger from '@/lib/logger';
import { PasswordService } from '@/modules/auth/services/password.services';

import { UserRepository } from '../data/users.repository';
import {
  type CreateUserInput,
  type UpdateUserInput,
  type UserApiResponse,
  SecurityLevel,
  PasswordStatus,
  type User,
  validationInputErrors,
} from '../models/users.entity';

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
   * Maps a User entity to an API response object.
   * @param user The user entity to map.
   * @returns The mapped API response or null if user is null.
   */
  mapToApiResponse(user: User | null): UserApiResponse | null {
    if (!user) return null;
    const apiUser = user.toApi() as UserApiResponse;
    if (user.createdAt) apiUser.createdTime = user.createdAt;
    if (user.updatedAt) apiUser.updatedTime = user.updatedAt;
    return apiUser;
  }

  /**
   * Retrieves a user by their ID.
   * @param id The user ID.
   * @param options Optional request context.
   * @returns The user API response.
   */
  async findById(
    id: number,
    options?: { requestingUser?: Request['user'] },
  ): Promise<UserApiResponse> {
    const requestingUser = options?.requestingUser;
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
      const apiResponse = this.mapToApiResponse(user);
      if (!apiResponse) {
        // This should theoretically not happen if findById found a user
        throw new ServerError(`Failed to map found user with id ${id} to API response.`);
      }
      return apiResponse;
    } catch (error) {
      if (error instanceof NotFoundError) {
        throw error;
      }
      throw new ServerError(`Error finding user with id ${id} ${error}`);
    }
  }

  /**
   * Retrieves a user by their email.
   * @param email The user's email address.
   * @returns The user API response.
   */
  async findByEmail(email: string): Promise<UserApiResponse> {
    try {
      const user = await this.userRepository.findByEmail(email);
      if (!user) throw new NotFoundError(`User with email ${email} not found.`);
      const apiResponse = this.mapToApiResponse(user);
      if (!apiResponse) {
        // This should theoretically not happen if findByEmail found a user
        throw new ServerError(`Failed to map found user with email ${email} to API response.`);
      }
      return apiResponse;
    } catch (error) {
      throw new ServerError(`Error finding user with email ${email} ${error}`);
    }
  }

  /**
   * Retrieves a user by email for authentication, including password.
   * @param email The user's email address.
   * @returns The user entity or null if not found.
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
   * Retrieves all users, filtered by the requesting user's rights.
   * @param options Optional request context.
   * @returns Array of user API responses.
   */
  async findAll(options?: { requestingUser?: Request['user'] }): Promise<UserApiResponse[]> {
    try {
      const where: FindOptionsWhere<User> = {};
      if (options?.requestingUser && !options.requestingUser.internal) {
        where.internal = false;
      }
      const { users } = await this.userRepository.findAll({ where });
      // Map and filter out any potential null results before returning
      return users.map((user) => this.mapToApiResponse(user)).filter(Boolean) as UserApiResponse[];
    } catch (error) {
      throw new ServerError(`Error finding all users ${error}`);
    }
  }

  /**
   * Creates a new user or reactivates a previously deleted user.
   * @param input The user creation input.
   * @param options Optional request context.
   * @returns The created or reactivated user API response.
   */
  async create(
    input: CreateUserInput,
    options?: { requestingUser?: Request['user'] },
  ): Promise<UserApiResponse> {
    const { password, email, permissions, permissionsExpireAt, ...restData } = input;
    if (!email) {
      throw new BadRequestError('Email is required.');
    }
    if (!password) {
      throw new BadRequestError('Password is required.');
    }
    const lowerCaseEmail = email.toLowerCase().trim();
    if (!this.passwordService.isPasswordValid(password)) {
      throw new BadRequestError(
        'Password does not meet complexity requirements (min. 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special character).',
      );
    }
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
      const apiResponse = this.mapToApiResponse(savedUser);
      if (!apiResponse) {
        // This should theoretically not happen after a successful save
        throw new ServerError(
          `Failed to map newly created/reactivated user ${savedUser.id} to API response.`,
        );
      }
      return apiResponse;
    } catch (error: any) {
      logger.error({
        message: `Original error caught during user creation/reactivation for ${email}`,
        originalError: error,
        originalStack: error?.stack,
      });
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
   * Updates an existing user's information.
   * @param id The user ID.
   * @param input The update input.
   * @param options Optional request context.
   * @returns The updated user API response.
   */
  async update(
    id: number,
    input: UpdateUserInput,
    options?: { requestingUser?: Request['user'] },
  ): Promise<UserApiResponse> {
    const { password, permissions, permissionsExpireAt, ...restData } = input;
    const requestingUser = options?.requestingUser;
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
      const apiResponse = this.mapToApiResponse(updatedUser);
      if (!apiResponse) {
        // This should theoretically not happen after a successful update and re-fetch
        throw new ServerError(`Failed to map updated user ${id} to API response.`);
      }
      return apiResponse;
    } catch (error: any) {
      logger.error(error, `Error updating user ${id}`);
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
   * Updates a user's preferences.
   * @param userId The user ID.
   * @param preferences The new preferences object or null.
   * @returns The updated user API response.
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
      const apiResponse = this.mapToApiResponse(updatedUser);
      if (!apiResponse) {
        // This should theoretically not happen after a successful preference update and re-fetch
        throw new ServerError(
          `Failed to map user ${userId} after preference update to API response.`,
        );
      }
      return apiResponse;
    } catch (error) {
      throw new ServerError(`Error updating preferences for user ${userId} ${error}`);
    }
  }

  /**
   * Resets a user's preferences to null.
   * @param userId The user ID.
   * @returns The updated user API response.
   */
  async resetPreferences(userId: number): Promise<UserApiResponse> {
    return this.updatePreferences(userId, null);
  }

  /**
   * Soft deletes a user (logical deletion).
   * @param id The user ID.
   * @param options Optional request context.
   * @returns void
   */
  async delete(id: number, options?: { requestingUser?: Request['user'] }): Promise<void> {
    const requestingUser = options?.requestingUser;
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

  /**
   * Returns a singleton instance of UsersService.
   * @returns The UsersService instance.
   */
  static getInstance(): UsersService {
    if (!instance) {
      instance = new UsersService(new UserRepository());
    }
    return instance;
  }
}
