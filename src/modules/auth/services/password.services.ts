import bcrypt from 'bcryptjs';
import { randomUUID } from 'crypto';
import dayjs from 'dayjs';
import { UserRepository } from '../../users/data/users.repository';
import logger from '@/lib/logger';
import config from '@/config';
import {
  NotFoundError,
  BadRequestError,
  ServerError,
  UnauthorizedError,
} from '@/common/errors/httpErrors';
import { getRedisClient, redisClient } from '@/lib/redis';
import { sendMail } from '@/lib/mailer';
import { User, PasswordStatus } from '../../users/models/users.entity';
import { renderTemplate } from '@/locales/emails';

const CONFIRM_CODE_EXPIRE_SECONDS = 60 * 60 * 24 * 3; // 3 days
const BCRYPT_SALT_ROUNDS = 10;
const PASSWORD_EXPIRED_IN_DAYS = 90;

let instance: PasswordService | null = null;

export class PasswordService {
  private readonly userRepository: UserRepository;

  constructor(userRepository: UserRepository = new UserRepository()) {
    this.userRepository = userRepository;
  }

  /**
   * Checks that a password:
   * - Is at least 8 characters long
   * - Contains at least one lowercase letter
   * - Contains at least one uppercase letter
   * - Contains at least one digit
   * - Contains at least one special character (@$!%*?&)
   * @param password - password input
   * @returns {boolean} - true if password valid
   */
  isPasswordValid(password: string): boolean {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
    return passwordRegex.test(password);
  }

  /**
   * Génère une chaîne aléatoire pour les codes de confirmation/réinitialisation
   */
  private generateRedisCode(): string {
    return randomUUID().replace(/-/g, '');
  }

  /**
   * Centralise le rendu des templates d'emails liés aux mots de passe
   */
  private renderPasswordEmailTemplate(
    type: 'passwordChanged' | 'passwordReset' | 'passwordConfirmation',
    user: User,
    context: { url?: string } = {},
    language: string = 'fr',
  ): { subject: string; html: string } {
    return renderTemplate(type, language, {
      name: user.name || '',
      url: context.url || '',
      app: config.MAIL_FROM || 'MyApp',
    });
  }

  /**
   * Hache un mot de passe avec bcrypt
   */
  async hashPassword(plainPassword: string): Promise<string> {
    return bcrypt.hash(plainPassword, BCRYPT_SALT_ROUNDS);
  }

  /**
   * Vérifie si un mot de passe est expiré
   */
  isPasswordExpired(passwordUpdatedAt: Date | null): boolean {
    if (!passwordUpdatedAt) return false;
    return dayjs(passwordUpdatedAt).add(PASSWORD_EXPIRED_IN_DAYS, 'days').isBefore(dayjs());
  }

  /**
   * Envoie un email de confirmation de changement de mot de passe
   */
  async sendPasswordConfirmationEmail(user: User, language: 'fr' | 'en' = 'en'): Promise<void> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      logger.error('Redis unavailable for password confirmation email.');
      throw new ServerError('Service temporarily unavailable (Redis)');
    }

    try {
      const code = this.generateRedisCode();
      const redisKey = `confirm-password:${code}`;

      await redis.setEx(redisKey, CONFIRM_CODE_EXPIRE_SECONDS, user.id.toString());
      const confirmationUrl = `${config.FRONTEND_URL || 'http://localhost:8080'}/confirm-password?code=${code}`;

      const { subject, html } = this.renderPasswordEmailTemplate(
        'passwordConfirmation',
        user,
        { url: confirmationUrl },
        language,
      );

      logger.info(`Sending password confirmation email to ${user.email} in language: ${language}`);
      await sendMail({ to: user.email, subject, html });
    } catch (error) {
      logger.error(error, `Failed to send password confirmation email to ${user.email}`);
    }
  }

  /**
   * Envoie un email de réinitialisation de mot de passe
   */
  async sendPasswordResetEmail(email: string, language: 'fr' | 'en' = 'en'): Promise<void> {
    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      logger.warn(`Password reset requested for unknown email: ${email}. No email sent.`);
      throw new UnauthorizedError(`Not found or Invalid email ${email}. No email sent`);
    }

    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      logger.error('Redis unavailable for password reset email.');
      throw new ServerError('Redis unavailable for password reset email.');
    }

    try {
      const code = this.generateRedisCode();
      const redisKey = `reset-password:${code}`;

      // Store user ID in Redis with expiration
      await redis.setEx(redisKey, CONFIRM_CODE_EXPIRE_SECONDS, user.id.toString());

      // Build reset URL
      const resetUrl = `${config.FRONTEND_URL || 'http://localhost:8080'}/reset-password?code=${code}`;

      const { subject, html } = this.renderPasswordEmailTemplate(
        'passwordReset',
        user,
        { url: resetUrl },
        language,
      );

      logger.info(`Sending password reset email to ${user.email} in language: ${language}`);
      await sendMail({ to: user.email, subject, html });
    } catch (error) {
      logger.error(error, `Failed to send password reset email to ${user.email}`);
    }
  }

  /**
   * Confirme un changement de mot de passe via un code
   */
  async confirmPasswordChange(code: string): Promise<boolean> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      throw new ServerError('Service temporarily unavailable (Redis)');
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
      throw new ServerError(`Failed to confirm password. ${error}`);
    }
  }

  /**
   * Réinitialise un mot de passe via un code
   */
  async resetPasswordWithCode(code: string, newPassword: string): Promise<boolean> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      throw new ServerError('Service temporarily unavailable (Redis)');
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

    const user = await this.userRepository.findByIdWithPassword(userId);
    if (!user) {
      await redis.del(redisKey);
      throw new NotFoundError('User associated with this reset code not found.');
    }

    if (!this.isPasswordValid(newPassword)) {
      throw new BadRequestError(
        'Password does not meet complexity requirements (min. 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special character)',
      );
    }

    const isSamePassword = await user.comparePassword(newPassword);
    if (isSamePassword) {
      throw new BadRequestError('New password cannot be the same as the old password.');
    }

    const hashedPassword = await this.hashPassword(newPassword);

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

      throw new ServerError(`Failed to reset password. ${error}`);
    }
  }

  /**
   * Mise à jour du statut de mot de passe d'un utilisateur
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
      throw new ServerError('Failed to update user password status.');
    }
  }

  /**
   * Change le mot de passe d'un utilisateur avec statut expiré
   */
  async updateExpiredPassword(email: string, newPassword: string): Promise<boolean> {
    const user = await this.userRepository.findByEmailWithPassword(email);
    if (!user) throw new NotFoundError('User not found');

    if (!this.isPasswordValid(newPassword)) {
      throw new BadRequestError('Password does not meet complexity requirements');
    }

    const isSame = await user.comparePassword(newPassword);
    if (isSame) throw new BadRequestError('New password must be different from the old one');

    user.password = await this.hashPassword(newPassword);
    user.passwordStatus = PasswordStatus.ACTIVE;
    user.passwordUpdatedAt = new Date();
    await this.userRepository.save(user);

    // Déterminer la langue à partir des préférences ou par défaut 'en'
    const language = user.preferences?.language || 'en';

    // Utiliser le template centralisé pour l'email de notification
    const { subject, html } = this.renderPasswordEmailTemplate(
      'passwordChanged',
      user,
      {},
      language,
    );

    try {
      await sendMail({
        to: user.email,
        subject,
        html,
      });
    } catch (e) {
      logger.error(e, `Error sending password change notification email to ${user.email}`);
    }

    return true;
  }

  static getInstance(): PasswordService {
    if (!instance) {
      instance = new PasswordService(new UserRepository());
    }
    return instance;
  }
}
