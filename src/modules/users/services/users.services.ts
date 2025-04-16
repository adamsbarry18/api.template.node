import bcrypt from 'bcrypt';
import { randomUUID } from 'crypto';
import { FindOptionsWhere } from 'typeorm';
import dayjs from 'dayjs';

import { User } from '../models/users.entity';
import { UserRepository } from '../data/users.repository';
import logger from '@/lib/logger';
import config from '@/config';
import {
  HttpError,
  NotFoundError,
  BadRequestError,
  ConflictError,
  ForbiddenError,
  InternalServerError,
} from '@/common/errors/httpErrors';
import { getRedisClient, redisClient } from '@/lib/redis';
import { sendMail } from '@/lib/mailer';
import { Request } from '@/config/http';
import {
  CreateUserInput,
  UpdateUserInput,
  UserApiResponse,
  PasswordStatus,
  SecurityLevel,
} from '../models/users.types';
import { AuthService } from '@/modules/auth/services/auth.services';

const CONFIRM_CODE_EXPIRE_SECONDS = 60 * 60 * 24 * 3; // 3 days
const BCRYPT_SALT_ROUNDS = 10;

export class UsersService {
  private readonly userRepository: UserRepository;
  private readonly authService: AuthService;

  /**
   * Creates an instance of UsersService.
   * @param {UserRepository} [userRepository=new UserRepository()] The user repository instance.
   * @param {AuthService} [authService] The auth service instance.
   */
  constructor(userRepository: UserRepository = new UserRepository(), authService?: AuthService) {
    this.userRepository = userRepository;
    this.authService = authService;
  }

  /**
   * Maps a User entity to a UserApiResponse object.
   * @param {User | null} user The user entity to map.
   * @returns {UserApiResponse | null} The mapped API response object, or null if the input user is null.
   */
  mapToApiResponse(user: User | null): UserApiResponse | null {
    if (!user) return null;
    return user.toApi() as UserApiResponse;
  }

  /**
   * Finds a user by their ID.
   * @param {number} id The ID of the user to find.
   * @returns {Promise<UserApiResponse>} The user data.
   * @throws {NotFoundError} If the user is not found.
   * @throws {InternalServerError} If there is a database error.
   */
  async findById(id: number): Promise<UserApiResponse> {
    try {
      const user = await this.userRepository.findById(id);
      if (!user) throw new NotFoundError(`User with id ${id} not found.`);
      return this.mapToApiResponse(user)!;
    } catch (error) {
      throw new InternalServerError(error, `Error finding user with id ${id}`);
    }
  }

  /**
   * Finds a user by their email address.
   * @param {string} email The email address of the user to find.
   * @returns {Promise<UserApiResponse>} The user data.
   * @throws {NotFoundError} If the user is not found.
   * @throws {InternalServerError} If there is a database error.
   */
  async findByEmail(email: string): Promise<UserApiResponse> {
    try {
      const user = await this.userRepository.findByEmail(email);
      if (!user) throw new NotFoundError(`User with email ${email} not found.`);
      return this.mapToApiResponse(user)!;
    } catch (error) {
      throw new InternalServerError(error, `Error finding user with email ${email}`);
    }
  }

  /**
   * Finds a user by email for authentication purposes, including the password hash.
   * This method should ONLY be used internally for authentication checks
   * and should NEVER be exposed via an API endpoint.
   * @param {string} email The email address of the user to find.
   * @returns {Promise<User | null>} The full user entity including password, or null if not found or on error.
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
   * Retrieves all users, potentially filtering out internal users based on the requestor.
   * @param {object} [options] Optional parameters.
   * @param {Request['user']} [options.requestingUser] The user making the request, used to determine if internal users should be included.
   * @returns {Promise<UserApiResponse[]>} A list of users.
   * @throws {InternalServerError} If there is a database error.
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
      throw new InternalServerError(error, 'Error finding all users');
    }
  }

  /**
   * Creates a new user or reactivates a previously soft-deleted user with the same email.
   * Handles password hashing, permission encoding, and validation.
   * @param {CreateUserInput} input The data for the new user.
   * @param {object} [options] Optional parameters.
   * @param {Request['user']} [options.requestingUser] The user making the request, used for authorization checks (e.g., creating internal users).
   * @returns {Promise<UserApiResponse>} The created or reactivated user's data.
   * @throws {BadRequestError} If the password does not meet complexity requirements or if user data is invalid.
   * @throws {ForbiddenError} If a non-internal user attempts to create an internal user.
   * @throws {ConflictError} If the email address is already in use by an active user or if a unique constraint is violated.
   * @throws {InternalServerError} If there is an unexpected error during creation or reactivation.
   */
  async create(
    input: CreateUserInput,
    options?: { requestingUser?: Request['user'] },
  ): Promise<UserApiResponse> {
    const { password, email, permissions, permissionsExpireAt, ...restData } = input;
    const lowerCaseEmail = email.toLowerCase().trim();
    const userModel = new User();
    if (!userModel.validatePassword(password)) {
      throw new BadRequestError('Password does not meet complexity requirements.');
    }
    const isInternalRequestor = !!options?.requestingUser?.internal;
    if (restData.internal && !isInternalRequestor) {
      throw new ForbiddenError('Cannot create internal user without being internal.');
    }
    const existingActiveUser = await this.userRepository.findByEmail(lowerCaseEmail);
    if (existingActiveUser) {
      throw new ConflictError('Email address is already in use by an active user.');
    }

    try {
      const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
      const encodedOverrides = AuthService.encodePermissionsToString(permissions ?? {});
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
        throw new BadRequestError('User data is invalid. ', userEntity.validationErrors);
      }

      const savedUser = await this.userRepository.save(userEntity);
      logger.info(`User ${savedUser.id} ${deletedUser ? 'reactivated' : 'created'} successfully.`);

      return this.mapToApiResponse(savedUser)!;
    } catch (error: any) {
      logger.error({
        message: `Original error caught during user creation/reactivation for ${lowerCaseEmail}`,
        originalError: error,
        originalStack: error?.stack,
      });

      if (error.code === '23505') {
        if (error.detail?.includes('(email)')) {
          throw new ConflictError('Email address already exists.');
        } else if (error.detail?.includes('(uid)')) {
          throw new ConflictError('Unique user identifier (UID) conflict.');
        } else {
          throw new ConflictError('Unique constraint violation during user creation.');
        }
      }

      throw error instanceof HttpError ? error : new InternalServerError('Failed to create user.');
    }
  }

  /**
   * Updates an existing user's information.
   * Handles password updates (including hashing and confirmation email), permission changes,
   * and authorization checks based on the requesting user's role (admin vs. self-update).
   * @param {number} id The ID of the user to update.
   * @param {UpdateUserInput} input The data to update the user with.
   * @param {object} [options] Optional parameters.
   * @param {Request['user']} [options.requestingUser] The user making the request, used for authorization checks.
   * @returns {Promise<UserApiResponse>} The updated user's data.
   * @throws {NotFoundError} If the user to update is not found.
   * @throws {ForbiddenError} If the requesting user lacks permission to update the target user or specific fields (level, internal).
   * @throws {BadRequestError} If the new password does not meet complexity requirements or if the resulting user data is invalid.
   * @throws {ConflictError} If the update violates a unique constraint (e.g., email).
   * @throws {InternalServerError} If there is an unexpected error during the update process.
   */
  async update(
    id: number,
    input: UpdateUserInput,
    options?: { requestingUser?: Request['user'] },
  ): Promise<UserApiResponse> {
    const { password, permissions, permissionsExpireAt, ...restData } = input;

    try {
      const user = await this.userRepository.findByIdWithPassword(id);
      if (!user) throw new NotFoundError(`User with id ${id} not found.`);

      const requestingUser = options?.requestingUser;
      const isSelfUpdate = requestingUser?.id === id;
      const isAdmin = requestingUser?.level === SecurityLevel.ADMIN;

      if (!isSelfUpdate && !isAdmin) {
        throw new ForbiddenError('You do not have permission to update this user.');
      }

      if (!isAdmin && (input.level !== undefined || input.internal !== undefined)) {
        throw new ForbiddenError('You do not have permission to change level or internal status.');
      }

      const updatePayload: Partial<User> = { ...restData };
      let passwordChanged = false;

      if (password) {
        if (!user.validatePassword(password)) {
          throw new BadRequestError('Password does not meet complexity requirements.');
        }

        const isSame = await user.comparePassword(password);
        if (!isSame) {
          updatePayload.password = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
          updatePayload.passwordUpdatedAt = new Date();
          updatePayload.passwordStatus = isAdmin
            ? PasswordStatus.ACTIVE
            : PasswordStatus.VALIDATING;
          passwordChanged = true;
        } else {
          logger.warn(`User ${id} attempted to update with the same password.`);
        }
      }

      if (permissions !== undefined) {
        updatePayload.authorisationOverrides = AuthService.encodePermissionsToString(
          permissions ?? {},
        );
      }
      if (permissionsExpireAt !== undefined) {
        const expiryDate = permissionsExpireAt ? dayjs(permissionsExpireAt) : null;
        updatePayload.permissionsExpireAt = expiryDate?.isValid() ? expiryDate.toDate() : null;
      }

      Object.assign(user, updatePayload);

      if (!user.isValid()) {
        throw new BadRequestError('User data after update is invalid.', user.validationErrors);
      }

      const result = await this.userRepository.update(id, updatePayload);
      if (result.affected === 0) {
        throw new NotFoundError(
          `User with id ${id} not found during update (or no changes applied).`,
        );
      }

      const updatedUser = await this.userRepository.findById(id);
      if (!updatedUser) throw new InternalServerError('Failed to re-fetch user after update.');
      if (passwordChanged && updatedUser.passwordStatus === PasswordStatus.VALIDATING) {
        const emailLanguage = updatedUser.preferences?.language === 'fr' ? 'fr' : 'en';
        await this.sendPasswordConfirmationEmail(updatedUser, emailLanguage);
      }

      logger.info(`User ${id} updated successfully.`);
      return this.mapToApiResponse(updatedUser)!;
    } catch (error: any) {
      logger.error(error, `Error updating user ${id}`);

      if (error.code === '23505') {
        throw new ConflictError('Update failed due to unique constraint violation (e.g., email).');
      }

      throw error instanceof HttpError ? error : new InternalServerError('Failed to update user.');
    }
  }

  /**
   * Updates the preferences JSON object for a specific user.
   * @param {number} userId The ID of the user whose preferences are to be updated.
   * @param {Record<string, any> | null} preferences The new preferences object, or null to clear preferences.
   * @returns {Promise<UserApiResponse>} The updated user data including the new preferences.
   * @throws {NotFoundError} If the user is not found.
   * @throws {InternalServerError} If there is a database error during the update or re-fetch.
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
        throw new InternalServerError('Failed to re-fetch user after preference update.');
      }

      return this.mapToApiResponse(updatedUser)!;
    } catch (error) {
      throw new InternalServerError(error, `Error updating preferences for user ${userId}`);
    }
  }

  /**
   * Resets a user's preferences by setting the preferences field to null.
   * @param {number} userId The ID of the user whose preferences are to be reset.
   * @returns {Promise<UserApiResponse>} The updated user data with preferences set to null.
   * @throws {NotFoundError} If the user is not found.
   * @throws {InternalServerError} If there is a database error.
   */
  async resetPreferences(userId: number): Promise<UserApiResponse> {
    return this.updatePreferences(userId, null);
  }

  /**
   * Soft-deletes a user by setting the `deletedAt` timestamp and anonymizing the email.
   * @param {number} id The ID of the user to soft-delete.
   * @returns {Promise<void>}
   * @throws {NotFoundError} If the user is not found.
   * @throws {InternalServerError} If there is a database error during the soft delete.
   */
  async delete(id: number): Promise<void> {
    try {
      const user = await this.userRepository.findById(id);
      if (!user) throw new NotFoundError(`User with id ${id} not found.`);

      // Anonymize email to avoid unique constraint issues
      const anonymizedEmail = `${user.email}_deleted_${Date.now()}`;
      await this.userRepository.softDelete(id, anonymizedEmail);

      logger.info(`User ${id} successfully soft-deleted.`);
    } catch (error) {
      throw new InternalServerError(error, `Error deleting user ${id}`);
    }
  }

  /**
   * Generates a random, URL-safe string suitable for use as a confirmation/reset code.
   * @private
   * @returns {string} A random code.
   */
  private generateRedisCode(): string {
    return randomUUID().replace(/-/g, '');
  }

  /**
   * Sends an email to the user asking them to confirm their recent password change.
   * Generates a unique code, stores it in Redis, and includes it in the confirmation link.
   * Supports localization ('fr' and 'en').
   * @param {User} user The user who changed their password.
   * @param {'fr' | 'en'} [language='en'] The language for the email template.
   * @returns {Promise<void>}
   */
  async sendPasswordConfirmationEmail(user: User, language: 'fr' | 'en' = 'en'): Promise<void> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      logger.error('Redis unavailable for password confirmation email.');
      return;
    }

    try {
      const code = this.generateRedisCode();
      const redisKey = `confirm-password:${code}`;

      // Store user ID in Redis with expiration
      await redis.setEx(redisKey, CONFIRM_CODE_EXPIRE_SECONDS, user.id.toString());

      // Build confirmation URL
      const confirmationUrl = `${config.FRONTEND_URL || 'http://localhost:8080'}/confirm-password?code=${code}`;

      // Define translations
      const translations = {
        fr: {
          subject: `[${config.MAIL_FROM || 'MyApp'}] Confirmation de mot de passe`,
          html: `
            <h2>Confirmation de votre nouveau mot de passe</h2>
            <p>Veuillez cliquer sur le lien suivant pour confirmer votre changement de mot de passe :</p>
            <p><a href="${confirmationUrl}">${confirmationUrl}</a></p>
            <p>Ce lien expire dans 3 jours.</p>
          `,
        },
        en: {
          subject: `[${config.MAIL_FROM || 'MyApp'}] Password confirmation`,
          html: `
            <h2>Confirm your new password</h2>
            <p>Please click the following link to confirm your password change:</p>
            <p><a href="${confirmationUrl}">${confirmationUrl}</a></p>
            <p>This link expires in 3 days.</p>
          `,
        },
      };

      // Select the appropriate translation (default to 'en' if language is invalid)
      const selectedTranslation = translations[language] || translations.en;

      logger.info(`Sending password confirmation email to ${user.email} in language: ${language}`);

      // Send the email
      await sendMail({
        to: user.email,
        subject: selectedTranslation.subject,
        html: selectedTranslation.html,
      });
    } catch (error) {
      logger.error(error, `Failed to send password confirmation email to ${user.email}`);
    }
  }

  /**
   * Confirms a user's password change using the provided confirmation code.
   * Verifies the code against Redis, updates the user's password status to ACTIVE,
   * and deletes the code from Redis upon success.
   * @param {string} code The confirmation code received by the user.
   * @returns {Promise<boolean>} True if the confirmation was successful.
   * @throws {HttpError} If Redis is unavailable (503).
   * @throws {BadRequestError} If the code is invalid, expired, or associated data is corrupt.
   * @throws {NotFoundError} If the user associated with the code is not found during the update.
   * @throws {InternalServerError} If there is an unexpected database error.
   */
  async confirmPasswordChange(code: string): Promise<boolean> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      throw new HttpError(503, 'Service temporarily unavailable (Redis)');
    }

    const redisKey = `confirm-password:${code}`;
    const userIdStr = await redis.get(redisKey);

    if (!userIdStr) {
      throw new BadRequestError('Invalid or expired confirmation code.');
    }

    const userId = parseInt(userIdStr, 10);
    if (isNaN(userId)) {
      await redis.del(redisKey);
      throw new BadRequestError('Invalid confirmation data.');
    }

    try {
      const result = await this.userRepository.updatePasswordStatus(userId, PasswordStatus.ACTIVE);

      if (result.affected === 0) {
        const userExists = await this.userRepository.exists({ id: userId });
        if (!userExists) {
          throw new NotFoundError('User not found during password confirmation.');
        }
      }

      await redis.del(redisKey);
      logger.info(`Password confirmed for user ${userId}`);
      return true;
    } catch (error) {
      await redis.del(redisKey);
      throw error instanceof HttpError
        ? error
        : new InternalServerError('Failed to confirm password.');
    }
  }

  /**
   * Sends a password reset email to the user if the email address exists in the system.
   * Generates a unique reset code, stores it in Redis, and includes it in the reset link.
   * Supports localization ('fr' and 'en'). Does not reveal if the email exists or not for security.
   * @param {string} email The email address to send the reset link to.
   * @param {'fr' | 'en'} [language='en'] The language for the email template.
   * @param {string} [referer] Optional referer information (not currently used in logic).
   * @returns {Promise<void>}
   */
  async sendPasswordResetEmail(
    email: string,
    language: 'fr' | 'en' = 'en',
    referer?: string,
  ): Promise<void> {
    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      logger.warn(`Password reset requested for unknown email: ${email}. No email sent.`);
      return;
    }

    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      logger.error('Redis unavailable for password reset email.');
      return;
    }

    try {
      const code = this.generateRedisCode();
      const redisKey = `reset-password:${code}`;

      // Store user ID in Redis with expiration
      await redis.setEx(redisKey, CONFIRM_CODE_EXPIRE_SECONDS, user.id.toString());

      // Build reset URL
      const resetUrl = `${config.FRONTEND_URL || 'http://localhost:8080'}/reset-password?code=${code}`;

      // Define translations
      const translations = {
        fr: {
          subject: `[${config.MAIL_FROM || 'MyApp'}] Réinitialisation de mot de passe`,
          html: `
            <h2>Réinitialisation de votre mot de passe</h2>
            <p>Vous avez demandé à réinitialiser votre mot de passe. Veuillez cliquer sur le lien suivant :</p>
            <p><a href="${resetUrl}">${resetUrl}</a></p>
            <p>Ce lien expire dans 3 jours.</p>
            <p>Si vous n'avez pas fait cette demande, vous pouvez ignorer cet email.</p>
          `,
        },
        en: {
          subject: `[${config.MAIL_FROM || 'MyApp'}] Password Reset`,
          html: `
            <h2>Password reset</h2>
            <p>You requested to reset your password. Please click the following link:</p>
            <p><a href="${resetUrl}">${resetUrl}</a></p>
            <p>This link expires in 3 days.</p>
            <p>If you did not make this request, you can ignore this email.</p>
          `,
        },
      };

      // Select the appropriate translation (default to 'en' if language is invalid)
      const selectedTranslation = translations[language] || translations.en;

      logger.info(`Sending password reset email to ${user.email} in language: ${language}`);

      // Send the email
      await sendMail({
        to: user.email,
        subject: selectedTranslation.subject,
        html: selectedTranslation.html,
      });
    } catch (error) {
      logger.error(error, `Failed to send password reset email to ${user.email}`);
    }
  }

  /**
   * Resets a user's password using a provided reset code and a new password.
   * Verifies the code against Redis, validates the new password complexity and difference
   * from the old password, hashes the new password, updates the user record, and deletes
   * the code from Redis.
   * @param {string} code The password reset code received by the user.
   * @param {string} newPassword The desired new password.
   * @returns {Promise<boolean>} True if the password reset was successful.
   * @throws {HttpError} If Redis is unavailable (503).
   * @throws {BadRequestError} If the code is invalid/expired, reset data is corrupt, the new password fails validation (complexity or same as old).
   * @throws {NotFoundError} If the user associated with the code is not found.
   * @throws {InternalServerError} If there is an unexpected database error during the update.
   */
  async resetPasswordWithCode(code: string, newPassword: string): Promise<boolean> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      throw new HttpError(503, 'Service temporarily unavailable (Redis)');
    }

    const redisKey = `reset-password:${code}`;
    const userIdStr = await redis.get(redisKey);

    if (!userIdStr) {
      throw new BadRequestError('Invalid or expired reset code.');
    }
    const userId = parseInt(userIdStr, 10);
    if (isNaN(userId)) {
      await redis.del(redisKey);
      throw new BadRequestError('Invalid reset data.');
    }

    // Find user (with password for comparison)
    const user = await this.userRepository.findByIdWithPassword(userId);
    // Validate the new password
    if (!user.validatePassword(newPassword)) {
      throw new BadRequestError('Password does not meet complexity requirements.');
    }

    if (!user) {
      await redis.del(redisKey);
      throw new NotFoundError('User associated with this reset code not found.');
    }

    const isSamePassword = await user.comparePassword(newPassword);
    if (isSamePassword) {
      throw new BadRequestError('New password cannot be the same as the old password.');
    }
    const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);

    try {
      const result = await this.userRepository.updatePasswordAndStatus(
        userId,
        hashedPassword,
        PasswordStatus.ACTIVE,
      );

      if (result.affected === 0) {
        throw new NotFoundError('User not found during password reset update.');
      }

      await redis.del(redisKey);
      logger.info(`Password reset successful for user ${userId}`);

      return true;
    } catch (error) {
      logger.error(error, `Error resetting password for user ${userId}`);
      await redis
        .del(redisKey)
        .catch((err) => logger.error(err, `Failed to delete reset key ${redisKey} after DB error`));

      throw error instanceof HttpError
        ? error
        : new InternalServerError('Failed to reset password.');
    }
  }

  /**
   * Directly updates the password status for a given user.
   * Primarily used internally, e.g., after successful password confirmation or administrative actions.
   * @param {number} userId The ID of the user whose password status is to be updated.
   * @param {PasswordStatus} status The new password status to set.
   * @returns {Promise<void>}
   * @throws {InternalServerError} If the database update fails.
   */
  async updatePasswordStatus(userId: number, status: PasswordStatus): Promise<void> {
    try {
      const result = await this.userRepository.update(userId, { passwordStatus: status });

      if (result.affected === 0) {
        logger.warn(
          `Attempted to update password status to ${status} for user ${userId}, but user was not found or no change was needed.`,
        );
      } else {
        logger.info(`Password status updated to ${status} for user ${userId}.`);
      }
    } catch (error) {
      logger.error(error, `Failed to update password status to ${status} for user ${userId}`);
      throw new InternalServerError('Failed to update user password status.');
    }
  }
}
