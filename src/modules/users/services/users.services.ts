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
import { Request } from '@/common/http';
// import { KeycloakService } from '@/lib/keycloak.service';
import {
  CreateUserInput,
  UpdateUserInput,
  UserApiResponse,
  PasswordStatus,
  SecurityLevel,
} from '../models/users.types';
import { AuthorisationsService } from '@/modules/auth/services/authorization.services';

const CONFIRM_CODE_EXPIRE_SECONDS = 60 * 60 * 24 * 3; // 3 jours
const BCRYPT_SALT_ROUNDS = 10;

function validatePasswordString(password: string): boolean {
  if (typeof password !== 'string') return false;
  if (password.length < 8) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  if (!/[ `!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/.test(password)) return false;
  return true;
}
export class UsersService {
  private readonly userRepository: UserRepository;
  private authorisationsService: AuthorisationsService;

  // Garder la référence commentée à KeycloakService
  // private keycloakServiceInstance: KeycloakService | null = null;

  constructor() {
    this.userRepository = new UserRepository();
    this.authorisationsService = new AuthorisationsService();
    this.authorisationsService = new AuthorisationsService();

    // --- Bloc Commenté Keycloak (Constructeur) ---
    /* Ne bloque pas le constructeur, la vérification se fera dans les méthodes
       if (config.KEYCLOAK_ENABLED) {
            KeycloakService.getInstance().then(instance => {
                if (instance.isServiceReady()) {
                    this.keycloakServiceInstance = instance;
                    logger.info('KeycloakService available to UsersService.');
                } else {
                    logger.warn('KeycloakService not ready for UsersService.');
                }
            }).catch(err => logger.error(err, "Failed to get KeycloakService instance in UsersService constructor"));
        }*/
    // --- Fin Bloc Commenté ---
  }

  /** Transformation vers UserApiResponse */
  mapToApiResponse(user: User | null): UserApiResponse | null {
    return user ? user.toApi() : null;
  }

  async findById(id: number): Promise<UserApiResponse> {
    const user = await this.userRepository.findById(id);
    if (!user) throw new NotFoundError(`User with id ${id} not found.`);
    return this.mapToApiResponse(user)!;
  }

  async findByEmail(email: string): Promise<UserApiResponse> {
    const user = await this.userRepository.findByEmail(email);
    if (!user) throw new NotFoundError(`User with email ${email} not found.`);
    return this.mapToApiResponse(user)!;
  }

  async findByEmailForAuth(email: string): Promise<User | null> {
    return await this.userRepository.findByEmailWithPassword(email);
  }

  async findAll(options?: { requestingUser?: Request['user'] }): Promise<UserApiResponse[]> {
    const where: FindOptionsWhere<User> = {};
    if (options?.requestingUser && !options.requestingUser.internal) {
      where.internal = false;
    }
    const { users } = await this.userRepository.findAll({ where });
    return users.map((user) => this.mapToApiResponse(user)!);
  }

  async create(
    input: CreateUserInput,
    options?: { requestingUser?: Request['user'] },
  ): Promise<UserApiResponse> {
    const { password, email, permissions, permissionsExpireAt, ...restData } = input;
    const lowerCaseEmail = email.toLowerCase().trim();
    if (!validatePasswordString(password)) {
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

    const deletedUser = await this.userRepository.findDeletedByEmail(lowerCaseEmail);
    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
    const encodedOverrides = this.authorisationsService.encodePermissionsToString(
      permissions ?? {},
    );

    try {
      let userEntity: User;
      let kcUserId: string | undefined;

      /* Tenter de créer l'utilisateur dans Keycloak d'abord (si activé)
         if (this.keycloakServiceInstance?.isServiceReady()) {
             try {
                 kcUserId = await this.keycloakServiceInstance.createUser({
                     email: lowerCaseEmail,
                     name: restData.name,
                     surname: restData.surname,
                     password: password // Keycloak gère le hash initial
                 });
                 logger.info(`Keycloak user created with ID: ${kcUserId} for email ${lowerCaseEmail}`);
             } catch (kcError: any) {
                 logger.error(kcError, `Failed to create Keycloak user for ${lowerCaseEmail}. Check Keycloak logs.`);
                 // Faut-il bloquer la création locale ? Pour l'instant, on continue, mais on pourrait throw.
                 // throw new InternalServerError(`Keycloak user creation failed: ${kcError.message}`);
             }
         } */
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
        deletedUser.uid = kcUserId ?? deletedUser.uid ?? randomUUID();
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
          uid: kcUserId ?? randomUUID(),
          passwordStatus: PasswordStatus.ACTIVE,
          passwordUpdatedAt: new Date(),
          authorisationOverrides: encodedOverrides,
          permissionsExpireAt: permissionsExpireAt ? dayjs(permissionsExpireAt).toDate() : null,
        });
      }
      const savedUser = await this.userRepository.save(userEntity);
      logger.info(
        `User ${savedUser.id} ${deletedUser ? 'reactivated' : 'created'} successfully locally.`,
      );

      return this.mapToApiResponse(savedUser)!;
    } catch (error: any) {
      logger.error(error, `Error during user creation/reactivation for ${lowerCaseEmail}`);

      /* Si Keycloak a créé l'utilisateur mais la DB locale a échoué, tenter de le supprimer dans Keycloak
         if (kcUserId && this.keycloakServiceInstance?.isServiceReady()) {
             logger.warn(`Rolling back Keycloak user creation for ID ${kcUserId} due to local DB error.`);
             await this.keycloakServiceInstance.deleteUser(kcUserId).catch(rbError =>
                 logger.error(rbError, `Failed to rollback Keycloak user ${kcUserId}`)
             );
         }*/

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
  async update(
    id: number,
    input: UpdateUserInput,
    options?: { requestingUser?: Request['user'] },
  ): Promise<UserApiResponse> {
    const { password, permissions, permissionsExpireAt, ...restData } = input;
    let permissionsOrExpiryChanged = false;

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
      if (!validatePasswordString(password))
        throw new BadRequestError('Password does not meet complexity requirements.');
      const isSame = await user.comparePassword(password);
      if (!isSame) {
        updatePayload.password = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
        updatePayload.passwordUpdatedAt = new Date();
        updatePayload.passwordStatus = isAdmin ? PasswordStatus.ACTIVE : PasswordStatus.VALIDATING;
        passwordChanged = true;
      } else {
        logger.warn(`User ${id} attempted to update with the same password.`);
      }
    }
    if (permissions !== undefined) {
      permissionsOrExpiryChanged = true;
      updatePayload.authorisationOverrides = this.authorisationsService.encodePermissionsToString(
        permissions ?? {},
      );
    }
    if (permissionsExpireAt !== undefined) {
      permissionsOrExpiryChanged = true;
      const expiryDate = permissionsExpireAt ? dayjs(permissionsExpireAt) : null;
      updatePayload.permissionsExpireAt = expiryDate?.isValid() ? expiryDate.toDate() : null;
    }

    if (input.level !== undefined && input.level !== user.level) permissionsOrExpiryChanged = true;
    if (input.internal !== undefined && input.internal !== user.internal)
      permissionsOrExpiryChanged = true;

    try {
      /* Mettre à jour Keycloak d'abord 
         let kcUpdateData: 
         if (restData.name !== undefined || restData.surname !== undefined) {
             kcUpdateData = { name: restData.name, surname: restData.surname };
         }
         if (passwordChanged && password) { // Envoyer le mot de passe en clair à Keycloak
              kcUpdateData = { ...(kcUpdateData ?? {}), password: password };
         }

         if (this.keycloakServiceInstance?.isServiceReady() && user.uid && kcUpdateData) {
              try {
                   await this.keycloakServiceInstance.updateUser(user.uid, kcUpdateData);
                   logger.info(`Keycloak user ${user.uid} updated successfully.`);
              } catch (kcError: any) {
                   logger.error(kcError, `Failed to update Keycloak user ${user.uid}. Proceeding with local update only.`);
                   // Faut-il bloquer l'update locale ? Pour l'instant, on continue.
                   // throw new InternalServerError(`Keycloak user update failed: ${kcError.message}`);
              }
         } */
      const result = await this.userRepository.update(id, updatePayload);
      if (result.affected === 0)
        throw new NotFoundError(
          `User with id ${id} not found during update (or no changes applied).`,
        );

      const updatedUser = await this.userRepository.findById(id);
      if (!updatedUser) throw new InternalServerError('Failed to re-fetch user after update.');
      if (passwordChanged && updatedUser.passwordStatus === PasswordStatus.VALIDATING) {
        await this.sendPasswordConfirmationEmail(updatedUser);
      }

      logger.info(`User ${id} updated successfully locally.`);
      return this.mapToApiResponse(updatedUser)!;
    } catch (error: any) {
      logger.error(error, `Error updating user ${id}`);
      if (error.code === '23505')
        throw new ConflictError('Update failed due to unique constraint violation (e.g., email).');
      throw error instanceof HttpError ? error : new InternalServerError('Failed to update user.');
    }
  }
  async updatePreferences(
    userId: number,
    preferences: Record<string, any> | null,
  ): Promise<UserApiResponse> {
    const result = await this.userRepository.update(userId, { preferences });
    if (result.affected === 0) throw new NotFoundError(`User with id ${userId} not found.`);
    const updatedUser = await this.userRepository.findById(userId);
    if (!updatedUser)
      throw new InternalServerError('Failed to re-fetch user after preference update.');
    return this.mapToApiResponse(updatedUser)!;
  }

  async resetPreferences(userId: number): Promise<UserApiResponse> {
    return this.updatePreferences(userId, null);
  }
  async delete(id: number): Promise<void> {
    const user = await this.userRepository.findById(id);
    if (!user) throw new NotFoundError(`User with id ${id} not found.`);

    /* Supprimer dans Keycloak d'abord
       if (this.keycloakServiceInstance?.isServiceReady() && user.uid) {
            try {
                 await this.keycloakServiceInstance.deleteUser(user.uid);
                 logger.info(`Keycloak user ${user.uid} deleted successfully.`);
            } catch (kcError: any) {
                 logger.error(kcError, `Failed to delete Keycloak user ${user.uid}. Proceeding with local deletion only.`);
                 // Continuer même si la suppression Keycloak échoue ?
            }
       }*/
    const anonymizedEmail = `${user.email}_deleted_${Date.now()}`;
    const result = await this.userRepository.softDelete(id, anonymizedEmail);
  }
  private generateRedisCode(): string {
    return randomUUID().replace(/-/g, '');
  }

  async sendPasswordConfirmationEmail(user: User): Promise<void> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      logger.error('Redis unavailable for pwd confirm email.');
      return;
    }
    try {
      const code = this.generateRedisCode();
      const redisKey = `confirm-password:${code}`;
      await redis.setEx(redisKey, CONFIRM_CODE_EXPIRE_SECONDS, user.id.toString());
      const confirmationUrl = `${config.FRONTEND_URL || 'http://localhost:8080'}/confirm-password?code=${code}`;
      const subject = `[${config.MAIL_FROM || 'MyApp'}] Confirmation de mot de passe / Password confirmation`;
      logger.info(`Sending password confirmation email to ${user.email}`);
      await sendMail({
        to: user.email,
        subject: subject,
        html: `<p>URL: <a href="${confirmationUrl}">${confirmationUrl}</a></p>`,
      });
    } catch (error) {
      logger.error(error, `Failed to send pwd confirmation email to ${user.email}`);
    }
  }

  async confirmPasswordChange(code: string): Promise<boolean> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) throw new HttpError(503, 'Service temporarily unavailable (Redis)');
    const redisKey = `confirm-password:${code}`;
    const userIdStr = await redis.get(redisKey);
    if (!userIdStr) throw new BadRequestError('Invalid or expired confirmation code.');
    const userId = parseInt(userIdStr, 10);
    if (isNaN(userId)) {
      await redis.del(redisKey);
      throw new BadRequestError('Invalid confirmation data.');
    }
    try {
      const result = await this.userRepository.updatePasswordStatus(userId, PasswordStatus.ACTIVE);
      if (result.affected === 0) {
        const userExists = await this.userRepository.exists({ id: userId });
        if (!userExists) throw new NotFoundError('User not found during password confirmation.');
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

  async sendPasswordResetEmail(email: string, referer?: string): Promise<void> {
    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      logger.warn(`Pwd reset requested for unknown email: ${email}. No email sent.`);
      return;
    }
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      logger.error('Redis unavailable for pwd reset email.');
      return;
    }
    try {
      const code = this.generateRedisCode();
      const redisKey = `reset-password:${code}`;
      await redis.setEx(redisKey, CONFIRM_CODE_EXPIRE_SECONDS, user.id.toString());
      const resetUrl = `${config.FRONTEND_URL || 'http://localhost:8080'}/reset-password?code=${code}`;
      const subject = `[${config.MAIL_FROM || 'MyApp'}] Réinitialisation de mot de passe / Password Reset`;
      logger.info(`Sending password reset email to ${user.email}`);
      await sendMail({
        to: user.email,
        subject: subject,
        html: `<p>URL: <a href="${resetUrl}">${resetUrl}</a></p>`,
      });
    } catch (error) {
      logger.error(error, `Failed to send pwd reset email to ${user.email}`);
    }
  }

  async resetPasswordWithCode(code: string, newPassword: string): Promise<boolean> {
    if (!validatePasswordString(newPassword))
      throw new BadRequestError('Password does not meet complexity requirements.');
    const redis = redisClient ?? getRedisClient();
    if (!redis) throw new HttpError(503, 'Service temporarily unavailable (Redis)');
    const redisKey = `reset-password:${code}`;
    const userIdStr = await redis.get(redisKey);
    if (!userIdStr) throw new BadRequestError('Invalid or expired reset code.');
    const userId = parseInt(userIdStr, 10);
    if (isNaN(userId)) {
      await redis.del(redisKey);
      throw new BadRequestError('Invalid reset data.');
    }

    const user = await this.userRepository.findByIdWithPassword(userId);
    if (!user) {
      await redis.del(redisKey);
      throw new NotFoundError('User associated with this reset code not found.');
    }

    const isSamePassword = await user.comparePassword(newPassword);
    if (isSamePassword)
      throw new BadRequestError('New password cannot be the same as the old password.');

    const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);

    /* Mettre à jour Keycloak d'abord
       if (this.keycloakServiceInstance?.isServiceReady() && user.uid) {
           try {
                // Le 'false' indique généralement que le changement n'est pas temporaire
                await this.keycloakServiceInstance.resetUserPassword(user.uid, newPassword, false);
                logger.info(`Keycloak password reset successfully for user ${user.id} (UID: ${user.uid})`);
           } catch (kcError: any) {
                logger.error(kcError, `Failed to reset Keycloak password for user ${user.id}. Proceeding with local reset only.`);
                // Continuer même si Keycloak échoue ?
                // throw new InternalServerError(`Keycloak password reset failed: ${kcError.message}`);
           }
       }*/

    try {
      const result = await this.userRepository.updatePasswordAndStatus(
        userId,
        hashedPassword,
        PasswordStatus.ACTIVE,
      );
      if (result.affected === 0)
        throw new NotFoundError('User not found during password reset update.');

      await redis.del(redisKey);
      logger.info(`Password reset successful for user ${userId}`);

      return true;
    } catch (error) {
      logger.error(error, `Error resetting password locally for user ${userId}`);
      await redis
        .del(redisKey)
        .catch((err) => logger.error(err, `Failed to delete reset key ${redisKey} after DB error`));
      throw error instanceof HttpError
        ? error
        : new InternalServerError('Failed to reset password.');
    }
  }

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
