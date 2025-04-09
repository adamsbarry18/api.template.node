import bcrypt from 'bcrypt';
// instanceToPlain n'est plus nécessaire
import { randomUUID } from 'crypto';
import { FindOptionsWhere } from 'typeorm';
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
import { getRedisClient } from '@/lib/redis';
import { sendMail } from '@/lib/mailer';
import { Request } from '@/common/http';
// import { KeycloakService } from '@/lib/keycloak.service'; // Service Keycloak (optionnel)
import {
  CreateUserInput,
  UpdateUserInput,
  UserApiResponse,
  PasswordStatus,
} from '../models/users.types';

const CONFIRM_CODE_EXPIRE_SECONDS = 60 * 60 * 24 * 3; // 3 jours en secondes
const BCRYPT_SALT_ROUNDS = 10; // Force de hachage

// --- Fonctions Utilitaires Locales ---
function validatePasswordString(password: string): boolean {
  if (typeof password !== 'string') return false;
  if (password.length < 8) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  if (!/[ `!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/.test(password)) return false;
  return true;
}

// --- Service Utilisateur ---
// Pas de décorateur @Injectable() ici
export class UsersService {
  // Déclaration des dépendances (repositories, autres services)
  private readonly userRepository: UserRepository;
  // Optionnel: Instance Keycloak (gérée via son propre getInstance/initialize)
  // private keycloakServiceInstance: KeycloakService | null = null;

  constructor() {
    // Instanciation directe des dépendances car pas de framework DI utilisé ici
    // Le UserRepository prend la DataSource globale par défaut
    this.userRepository = new UserRepository();

    // Tentative d'obtenir l'instance Keycloak (si activé)
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
  }

  /**
   * Transformation de l'entité User en objet pour l'API (exclut les données sensibles).
   * @param user - L'entité User ou null.
   * @returns L'objet UserApiResponse ou null.
   */
  private mapToApiResponse(user: User | null): UserApiResponse | null {
    return user ? user.toApi() : null;
  }

  /** Récupère un utilisateur par ID (non supprimé). Lance NotFoundError si non trouvé. */
  async findById(id: number): Promise<UserApiResponse> {
    const user = await this.userRepository.findById(id);
    if (!user) throw new NotFoundError(`User with id ${id} not found.`);
    return this.mapToApiResponse(user)!; // Non-null assertion car on a vérifié
  }

  /** Récupère un utilisateur par Email (non supprimé). Lance NotFoundError si non trouvé. */
  async findByEmail(email: string): Promise<UserApiResponse> {
    const user = await this.userRepository.findByEmail(email);
    if (!user) throw new NotFoundError(`User with email ${email} not found.`);
    return this.mapToApiResponse(user)!;
  }

  /** Récupère un utilisateur par Email pour authentification (retourne l'entité complète ou null). */
  async findByEmailForAuth(email: string): Promise<User | null> {
    return await this.userRepository.findByEmailWithPassword(email);
  }

  /** Liste les utilisateurs (avec filtres optionnels). */
  async findAll(options?: { requestingUser?: Request }): Promise<UserApiResponse[]> {
    const where: FindOptionsWhere<User> = {};
    if (options?.requestingUser && !options.requestingUser.internal) {
      where.internal = false; // Filtrer les utilisateurs internes si l'appelant n'est pas interne
    }
    // TODO: Ajouter pagination ici si nécessaire (options.skip, options.take)
    const { users } = await this.userRepository.findAll({ where });
    return users.map((user) => this.mapToApiResponse(user)!);
  }

  /** Crée un nouvel utilisateur ou réactive un utilisateur supprimé. */
  async create(
    input: CreateUserInput,
    options?: { requestingUser?: Request },
  ): Promise<UserApiResponse> {
    const { password, email, authorisationOverrides, permissionsExpireAt, ...restData } = input;
    const lowerCaseEmail = email.toLowerCase().trim();

    // Validations métier
    if (!validatePasswordString(password)) {
      throw new BadRequestError('Password does not meet complexity requirements.');
    }
    const isInternalRequestor = !!options?.requestingUser?.internal;
    if (restData.internal && !isInternalRequestor) {
      throw new ForbiddenError('Cannot create internal user.');
    }
    if (await this.userRepository.checkEmailExists(lowerCaseEmail)) {
      throw new ConflictError('Email address is already in use.');
    }

    const deletedUser = await this.userRepository.findDeletedByEmail(lowerCaseEmail);
    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    try {
      let userEntity: User;
      let kcUserId: string | undefined;

      /*Tenter de créer l'utilisateur dans Keycloak d'abord (si activé)
            if (this.keycloakServiceInstance?.isServiceReady()) {
                try {
                    kcUserId = await this.keycloakServiceInstance.createUser({
                        email: lowerCaseEmail,
                        name: restData.name,
                        surname: restData.surname,
                        password: password // Keycloak gère le hash initial
                    });
                    logger.info(`Keycloak user created with ID: ${kcUserId}`);
                } catch (kcError: any) {
                    logger.error(kcError, `Failed to create Keycloak user for ${lowerCaseEmail}. Check Keycloak logs.`);
                    // Faut-il bloquer la création locale ? Pour l'instant, on continue.
                    // throw new InternalServerError(`Keycloak user creation failed: ${kcError.message}`);
                }
            }*/

      // Logique de création/réactivation dans la base de données locale
      if (deletedUser) {
        logger.info(
          `Reactivating deleted user with email ${lowerCaseEmail} (ID: ${deletedUser.id})`,
        );
        // Mettre à jour l'entité existante
        Object.assign(deletedUser, restData);
        deletedUser.deletedAt = null;
        deletedUser.email = lowerCaseEmail;
        deletedUser.password = hashedPassword;
        deletedUser.passwordStatus = PasswordStatus.ACTIVE;
        deletedUser.passwordUpdatedAt = new Date();
        deletedUser.uid = kcUserId ?? deletedUser.uid ?? randomUUID();
        deletedUser.authorisationOverrides = authorisationOverrides ?? null;
        deletedUser.permissionsExpireAt = permissionsExpireAt ?? null;
        userEntity = deletedUser;
      } else {
        // Créer une nouvelle entité
        userEntity = this.userRepository.create({
          ...restData,
          email: lowerCaseEmail,
          password: hashedPassword,
          uid: kcUserId ?? randomUUID(),
          passwordStatus: PasswordStatus.ACTIVE,
          passwordUpdatedAt: new Date(),
          authorisationOverrides: authorisationOverrides ?? null,
          permissionsExpireAt: permissionsExpireAt ?? null,
        });
      }

      // Sauvegarder l'entité (insert ou update)
      const savedUser = await this.userRepository.save(userEntity);
      logger.info(
        `User ${savedUser.id} ${deletedUser ? 'reactivated' : 'created'} successfully locally.`,
      );
      return this.mapToApiResponse(savedUser)!;
    } catch (error: any) {
      logger.error(error, `Error during user creation/reactivation for ${lowerCaseEmail}`);

      /* Si Keycloak a créé l'utilisateur mais la DB locale a échoué, on pourrait tenter de supprimer l'utilisateur Keycloak
            if (kcUserId && this.keycloakServiceInstance?.isServiceReady()) {
                logger.warn(`Rolling back Keycloak user creation for ID ${kcUserId} due to local DB error.`);
                await this.keycloakServiceInstance.deleteUser(kcUserId).catch(rbError => logger.error(rbError, `Failed to rollback Keycloak user ${kcUserId}`));
            }*/

      // Gérer les erreurs spécifiques (ex: contrainte unique)
      if (error.code === '23505') throw new ConflictError('Email address or UID already exists.');
      throw new InternalServerError('Failed to create user.');
    }
  }

  /** Met à jour un utilisateur existant */
  async update(
    id: number,
    input: UpdateUserInput,
    options?: { requestingUser?: Request },
  ): Promise<UserApiResponse> {
    const { password, authorisationOverrides, permissionsExpireAt, ...restData } = input;

    const user = await this.userRepository.findById(id);
    if (!user) throw new NotFoundError(`User with id ${id} not found.`);

    const isInternalRequestor = !!options?.requestingUser?.internal;
    // ... validations de permissions (internal, level) ...

    const updatePayload: Partial<User> = { ...restData };
    let passwordChanged = false;
    let localPasswordHashed: string | undefined;

    // Gestion de la mise à jour du mot de passe
    if (password) {
      if (!validatePasswordString(password))
        throw new BadRequestError('Password does not meet complexity requirements.');
      const isSame = await user.comparePassword(password);
      if (!isSame) {
        localPasswordHashed = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
        updatePayload.password = localPasswordHashed; // Préparer pour la BDD locale
        updatePayload.passwordUpdatedAt = new Date();
        updatePayload.passwordStatus = isInternalRequestor
          ? PasswordStatus.ACTIVE
          : PasswordStatus.VALIDATING;
        passwordChanged = true;
      } else {
        logger.warn(`User ${id} attempted to update with the same password.`);
      }
    }

    // Mise à jour des overrides d'autorisation
    if (authorisationOverrides !== undefined)
      updatePayload.authorisationOverrides = authorisationOverrides;
    if (permissionsExpireAt !== undefined) updatePayload.permissionsExpireAt = permissionsExpireAt;

    try {
      /* Mettre à jour Keycloak d'abord (si applicable et si des données pertinentes ont changé)
            let kcUpdateData: Partial<SimpleUserData> | null = null;
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
                 }
            }*/

      // Mettre à jour l'utilisateur local via le repository
      const result = await this.userRepository.update(id, updatePayload);
      if (result.affected === 0)
        throw new NotFoundError(`User with id ${id} not found during update.`);

      const updatedUser = await this.userRepository.findById(id); // Re-fetch
      if (!updatedUser) throw new InternalServerError('Failed to re-fetch user after update.');

      // Envoyer l'email de confirmation si nécessaire
      if (passwordChanged && updatedUser.passwordStatus === PasswordStatus.VALIDATING) {
        await this.sendPasswordConfirmationEmail(updatedUser);
      }

      logger.info(`User ${id} updated successfully locally.`);
      return this.mapToApiResponse(updatedUser)!;
    } catch (error: any) {
      logger.error(error, `Error updating user ${id}`);
      if (error.code === '23505')
        throw new ConflictError('Update failed due to unique constraint violation.');
      throw error;
    }
  }

  /** Met à jour les préférences utilisateur */
  async updatePreferences(
    userId: number,
    preferences: Record<string, any> | null,
  ): Promise<UserApiResponse> {
    const result = await this.userRepository.update(userId, { preferences });
    if (result.affected === 0) throw new NotFoundError(`User with id ${userId} not found.`);
    const updatedUser = await this.userRepository.findById(userId);
    return this.mapToApiResponse(updatedUser)!;
  }

  /** Réinitialise les préférences utilisateur */
  async resetPreferences(userId: number): Promise<UserApiResponse> {
    return this.updatePreferences(userId, null);
  }

  /** Supprime (soft delete) un utilisateur */
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

    // Soft delete local
    const anonymizedEmail = `${user.email}_deleted_${Date.now()}`;
    const result = await this.userRepository.softDelete(id, anonymizedEmail);
    if (result.affected === 0) {
      // L'utilisateur a pu être supprimé entre le findById et le softDelete
      logger.warn(`User with id ${id} may have already been deleted.`);
      // throw new NotFoundError(`User with id ${id} not found or already deleted during soft delete.`);
    } else {
      logger.info(`User ${id} soft deleted successfully locally.`);
    }
    // Pas besoin de supprimer les autorisations car elles sont sur l'utilisateur
  }

  // --- Logique liée au mot de passe (confirmation, réinitialisation) ---

  private generateRedisCode(): string {
    return randomUUID().replace(/-/g, '');
  }

  async sendPasswordConfirmationEmail(user: User, referer?: string): Promise<void> {
    const redis = getRedisClient();
    if (!redis) {
      logger.error('Redis unavailable for pwd confirm email.');
      return;
    }
    try {
      const code = this.generateRedisCode();
      const redisKey = `confirm-password:${code}`; // Clé simple code -> userId
      await redis.setEx(redisKey, CONFIRM_CODE_EXPIRE_SECONDS, user.id.toString());
      const confirmationUrl = `${config.CORS_ORIGIN || 'http://localhost:8080'}/confirm-password?code=${code}`;
      const subject = `[${config.MAIL_FROM || 'MyApp'}] Confirmation de mot de passe / Password confirmation`;
      logger.info(`Sending password confirmation email to ${user.email}`);
      await sendMail({
        to: user.email,
        subject: subject,
        html: `<p>Pour confirmer cliquez : <a href="${confirmationUrl}">Confirmer</a></p><p>To confirm click: <a href="${confirmationUrl}">Confirm</a></p>`,
      });
    } catch (error) {
      logger.error(error, `Failed to send pwd confirmation email to ${user.email}`);
    }
  }

  async confirmPasswordChange(code: string): Promise<boolean> {
    const redis = getRedisClient();
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
      if (result.affected === 0)
        throw new BadRequestError(
          'Password confirmation failed (user not found or status invalid).',
        );
      await redis.del(redisKey);
      logger.info(`Password confirmed for user ${userId}`);
      // this.emitChange('password', userId);
      return true;
    } catch (error) {
      logger.error(error, `Error confirming password for user ${userId}`);
      throw error;
    }
  }

  async sendPasswordResetEmail(email: string, referer?: string): Promise<void> {
    const user = await this.userRepository.findByEmail(email); // Pas besoin du hash ici
    if (!user) {
      logger.warn(`Pwd reset requested for unknown email: ${email}`);
      return;
    }
    const redis = getRedisClient();
    if (!redis) {
      logger.error('Redis unavailable for pwd reset email.');
      return;
    }
    try {
      const code = this.generateRedisCode();
      const redisKey = `reset-password:${code}`;
      await redis.setEx(redisKey, CONFIRM_CODE_EXPIRE_SECONDS, user.id.toString());
      const resetUrl = `${config.CORS_ORIGIN || 'http://localhost:8080'}/reset-password?code=${code}`;
      const subject = `[${config.MAIL_FROM || 'MyApp'}] Réinitialisation de mot de passe / Password Reset`;
      logger.info(`Sending password reset email to ${user.email}`);
      await sendMail({
        to: user.email,
        subject: subject,
        html: `<p>Pour réinitialiser cliquez : <a href="${resetUrl}">Réinitialiser</a></p><p>To reset click: <a href="${resetUrl}">Reset</a></p>`,
      });
    } catch (error) {
      logger.error(error, `Failed to send pwd reset email to ${user.email}`);
    }
  }

  async resetPasswordWithCode(code: string, newPassword: string): Promise<boolean> {
    if (!validatePasswordString(newPassword))
      throw new BadRequestError('Password does not meet complexity requirements.');
    const redis = getRedisClient();
    if (!redis) throw new HttpError(503, 'Service temporarily unavailable (Redis)');
    const redisKey = `reset-password:${code}`;
    const userIdStr = await redis.get(redisKey);
    if (!userIdStr) throw new BadRequestError('Invalid or expired reset code.');
    const userId = parseInt(userIdStr, 10);
    if (isNaN(userId)) {
      await redis.del(redisKey);
      throw new BadRequestError('Invalid reset data.');
    }

    // Récupérer l'utilisateur via repository
    const user = await this.userRepository.findById(userId);
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
                 await this.keycloakServiceInstance.resetUserPassword(user.uid, newPassword, false);
                 logger.info(`Keycloak password reset for user ${user.id}`);
            } catch (kcError: any) {
                 logger.error(kcError, `Failed to reset Keycloak password for user ${user.id}. Proceeding with local reset only.`);
                 // Continuer même si Keycloak échoue ?
            }
        }*/

    try {
      // Mettre à jour localement via repository
      const result = await this.userRepository.updatePasswordAndStatus(
        userId,
        hashedPassword,
        PasswordStatus.ACTIVE,
      );
      if (result.affected === 0)
        throw new NotFoundError('User not found during password reset update.');

      await redis.del(redisKey); // Supprimer le code Redis
      logger.info(`Password reset successful for user ${userId}`);
      // this.emitChange('password', userId);
      // Envoyer notification ?
      return true;
    } catch (error) {
      logger.error(error, `Error resetting password for user ${userId}`);
      throw error;
    }
  }
}
