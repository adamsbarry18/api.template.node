import bcrypt from 'bcryptjs';
import dayjs from 'dayjs';
import { nanoid } from 'nanoid';

import {
  NotFoundError,
  BadRequestError,
  ServerError,
  UnauthorizedError,
  ParameterError,
  PARAMETER_ERRORS,
} from '@/common/errors/httpErrors';
import config from '@/config';
import logger from '@/lib/logger';
import { sendMail } from '@/lib/mailer';
import { getRedisClient, redisClient } from '@/lib/redis';
import { renderTemplate } from '@/locales/emails';

import { UserRepository } from '../../users/data/users.repository';
import { type User, PasswordStatus } from '@/modules/users/models/users.entity';

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
   * Checks if a password meets complexity requirements:
   * - At least 8 characters
   * - At least one lowercase letter
   * - At least one uppercase letter
   * - At least one digit
   * - At least one special character (@$!%*?&)
   * @param password The password to validate
   * @returns True if the password is valid, false otherwise
   */
  isPasswordValid(password: string): boolean {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
    return passwordRegex.test(password);
  }

  /**
   * Renders the email template for password-related actions.
   * @param type The type of password email (changed, reset, confirmation)
   * @param user The user object
   * @param context Additional context such as URL
   * @param language The language for the email template
   * @returns An object containing subject and HTML content
   */
  private renderPasswordEmailTemplate(
    type: 'passwordChanged' | 'passwordReset' | 'passwordConfirmation',
    user: User,
    context: { url?: string } = {},
    language: string = 'fr',
  ): { subject: string; html: string } {
    return renderTemplate(type, language, {
      name: user.lastName || '',
      url: context.url || '',
      app: config.MAIL_FROM || 'MyApp',
    });
  }

  /**
   * Hashes a plain password using bcrypt.
   * @param plainPassword The plain text password to hash
   * @returns The hashed password as a string
   */
  async hashPassword(plainPassword: string): Promise<string> {
    return bcrypt.hash(plainPassword, BCRYPT_SALT_ROUNDS);
  }

  /**
   * Checks if a password is expired based on the last update date.
   * @param passwordUpdatedAt The date when the password was last updated
   * @returns True if the password is expired, false otherwise
   */
  isPasswordExpired(passwordUpdatedAt: Date | null): boolean {
    if (!passwordUpdatedAt) return false;
    return dayjs(passwordUpdatedAt).add(PASSWORD_EXPIRED_IN_DAYS, 'days').isBefore(dayjs());
  }

  /**
   * Sends a password confirmation email to the user.
   * @param user The user to send the email to
   * @param referer Optional referer URL for generating the confirmation link
   * @returns A promise that resolves when the email is sent
   */
  async sendPasswordConfirmationEmail(user: User, referer?: string): Promise<void> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      logger.error('Redis unavailable for password confirmation email.');
      throw new ServerError('Service temporarily unavailable (Redis)');
    }

    try {
      const code = nanoid(32);
      let url = referer;
      if (url?.endsWith('/')) url = url.substring(0, url.length - 1);
      if (!url) url = config.FRONTEND_URL || 'http://localhost:8080';
      await redis.setEx(
        `api:users:confirm-password:${code}`,
        CONFIRM_CODE_EXPIRE_SECONDS,
        user.id.toString(),
      );
      // Format URL pour createWebHashHistory: http://host/#/path?query
      const confirmationUrl = `${url}/#/confirm-password?code=${code}`;
      const language = user.preferences?.language || 'en';
      const { subject, html } = this.renderPasswordEmailTemplate(
        'passwordConfirmation',
        user,
        { url: confirmationUrl },
        language,
      );
      await sendMail({ to: user.email, subject, html });
    } catch (error) {
      logger.error(error, `Failed to send password confirmation email to ${user.email}`);
    }
  }

  /**
   * Sends a password reset email to the user.
   * @param email The user's email address
   * @param referer Optional referer URL for generating the reset link
   * @param language Optional language for the email
   * @returns A promise that resolves when the email is sent
   */
  async sendPasswordResetEmail(
    email: string,
    referer?: string,
    language?: 'fr' | 'en',
  ): Promise<void> {
    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      throw new UnauthorizedError(`Not found or Invalid email ${email}. No email sent`);
    }

    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      logger.error('Redis unavailable for password reset email.');
      throw new ServerError('Redis unavailable for password reset email.');
    }

    try {
      const code = nanoid(32);
      let url = referer;
      if (url?.endsWith('/')) url = url.substring(0, url.length - 1);
      if (!url) url = config.FRONTEND_URL || 'http://localhost:8080';
      await redis.setEx(
        `api:users:reset-password:${code}`,
        CONFIRM_CODE_EXPIRE_SECONDS,
        user.id.toString(),
      );
      // Format URL pour createWebHashHistory: http://host/#/path?query
      const resetUrl = `${url}/#/reset-password?code=${code}`;
      const lang = language || user.preferences?.language || 'en';
      const { subject, html } = this.renderPasswordEmailTemplate(
        'passwordReset',
        user,
        { url: resetUrl },
        lang,
      );
      await sendMail({ to: user.email, subject, html });
    } catch (error) {
      logger.error(error, `Failed to send password reset email to ${user.email}`);
    }
  }

  /**
   * Confirms a password change using a confirmation code.
   * @param code The confirmation code from the email
   * @returns True if the password status was confirmed
   */
  async confirmPasswordChange(code: string): Promise<boolean> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      throw new ServerError('Service temporarily unavailable (Redis)');
    }

    const redisKey = `api:users:confirm-password:${code}`;
    const userIdStr = await redis.get(redisKey);

    if (!userIdStr) {
      throw new BadRequestError('Invalid or expired confirmation code.');
    }

    const userId = parseInt(userIdStr, 10);
    if (isNaN(userId)) {
      await redis.del(redisKey);
      throw new BadRequestError('Invalid confirmation data.');
    }

    const user = await this.userRepository.findById(userId);
    if (!user) {
      await redis.del(redisKey);
      throw new NotFoundError('User not found during password confirmation.');
    }

    try {
      await redis.del(redisKey);
    } catch (delError) {
      logger.error(delError, `[confirmPasswordChange] Failed to delete Redis key: ${redisKey}`);
    }
    await this.userRepository.updatePasswordStatus(userId, PasswordStatus.ACTIVE);
    return true;
  }

  /**
   * Resets a user's password using a reset code.
   * @param code The reset code from the email
   * @param newPassword The new password to set
   * @returns True if the password was reset successfully
   */
  async resetPasswordWithCode(code: string, newPassword: string): Promise<boolean> {
    const redis = redisClient ?? getRedisClient();
    if (!redis) {
      throw new ServerError('Service temporarily unavailable (Redis)');
    }

    const redisKey = `api:users:reset-password:${code}`;
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

      try {
        await redis.del(redisKey);
      } catch (delError) {
        logger.error(delError, `[resetPasswordWithCode] Failed to delete Redis key: ${redisKey}`);
      }
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
   * Updates the password status for a user.
   * @param userId The user's ID
   * @param status The new password status
   * @returns A promise that resolves when the status is updated
   */
  async updatePasswordStatus(userId: number, status: PasswordStatus): Promise<void> {
    try {
      const result = await this.userRepository.updatePasswordStatus(userId, status);

      if (result.affected === 0) {
        logger.warn(
          `Attempted to update password status to ${status} for user ${userId}, but user was not found or no change was needed.`,
        );
      }
    } catch (error) {
      logger.error(error, `Failed to update password status to ${status} for user ${userId}`);
      throw new ServerError('Failed to update user password status.');
    }
  }

  /**
   * Changes the password for a user whose password.
   * @param params Object containing userId or email, new password, and optional referer
   * @returns True if the password was updated and confirmation email sent
   */
  async updatePassword(params: {
    userId?: number;
    email?: string;
    password: string;
    referer?: string;
    sendConfirmationEmail?: boolean;
  }): Promise<boolean> {
    const { userId, email, password, referer, sendConfirmationEmail = true } = params;
    if (!userId && !email) throw new NotFoundError('userId or email have to be provided');
    let user: User | null = null;
    if (userId) {
      user = await this.userRepository.findByIdWithPassword(userId);
    } else if (email) {
      user = await this.userRepository.findByEmailWithPassword(email);
    }
    if (!user) throw new NotFoundError('Could not find user');

    if (!this.isPasswordValid(password)) {
      throw new BadRequestError('Password security is too low');
    }

    const hashedInputPassword = await this.hashPassword(password);
    if (hashedInputPassword === user.password) {
      throw new ParameterError(PARAMETER_ERRORS.PASSWORD_IDENTICAL);
    }

    const isSame = await user.comparePassword(password);
    if (isSame) throw new BadRequestError('New password must be different from the old one');

    const hashedPassword = await this.hashPassword(password);
    const newStatus = sendConfirmationEmail ? PasswordStatus.VALIDATING : PasswordStatus.ACTIVE;
    await this.userRepository.updatePasswordAndStatus(user.id, hashedPassword, newStatus);
    if (sendConfirmationEmail) {
      await this.sendPasswordConfirmationEmail(user, referer);
    }

    return true;
  }

  /**
   * Returns a singleton instance of PasswordService.
   * @returns The PasswordService instance
   */
  static getInstance(): PasswordService {
    if (!instance) {
      instance = new PasswordService(new UserRepository());
    }
    return instance;
  }
}
