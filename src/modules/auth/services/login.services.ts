import jwt from 'jsonwebtoken';
import { redisClient } from '@/lib/redis';
import config from '@/config';
import logger from '@/lib/logger';
import { UnauthorizedError, ServerError } from '@/common/errors/httpErrors';
import { UserRepository } from '@/modules/users/data/users.repository';
import { PasswordStatus, UserApiResponse } from '@/modules/users/models/users.entity';
import { UsersService } from '@/modules/users/services/users.services';
import { PasswordService } from './password.services';

const REDIS_TOKEN_INVALIDATION_KEY = 'api-auth:token_invalidation:{token}';
const TOKEN_DEFAULT_EXPIRE_SECONDS = 60 * 60 * 24 * 30; // 30 jours

let instance: LoginService | null = null;

export class LoginService {
  private readonly usersService: UsersService;
  private readonly passwordService: PasswordService;

  constructor(
    userRepository: UserRepository = new UserRepository(),
    usersService?: UsersService,
    passwordService?: PasswordService,
  ) {
    this.usersService = usersService ?? new UsersService(userRepository);
    this.passwordService = passwordService ?? new PasswordService(userRepository);
  }

  /**
   * Génère la clé Redis pour l'invalidation d'un token
   */
  private getRedisInvalidationKey(token: string): string {
    return REDIS_TOKEN_INVALIDATION_KEY.replace('{token}', token);
  }

  /**
   * Authentifie un utilisateur en vérifiant email et mot de passe
   */
  async login(email: string, password: string): Promise<{ token: string; user: UserApiResponse }> {
    if (!email || !password) {
      throw new UnauthorizedError('Email and password required.');
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await this.usersService.findByEmailForAuth(normalizedEmail);
    if (!user) {
      throw new UnauthorizedError('Invalid email or password.');
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      logger.error(`Incorrect password for user ID: ${user.id}`);
      throw new UnauthorizedError('Invalid email or password.');
    }

    if (user.passwordStatus === PasswordStatus.VALIDATING) {
      throw new UnauthorizedError('Password validation in progress.');
    }

    const passwordExpired = this.passwordService.isPasswordExpired(user.passwordUpdatedAt);

    if (user.passwordStatus === PasswordStatus.EXPIRED || passwordExpired) {
      if (user.passwordStatus !== PasswordStatus.EXPIRED) {
        await this.passwordService.updatePasswordStatus(user.id, PasswordStatus.EXPIRED);
      }
      throw new UnauthorizedError('Password expired.');
    }

    const token = await this.signToken(user.id, { level: user.level, internal: user.internal });
    const userApi = this.usersService.mapToApiResponse(user);
    return { user: userApi!, token };
  }

  /**
   * Déconnecte un utilisateur en invalidant son token
   */
  async logout(token: string): Promise<void> {
    if (!token) return;
    await this.invalidateToken(token);
  }

  /**
   * Signe un token JWT pour un utilisateur
   */
  async signToken(userId: number, extraPayload: Record<string, any> = {}): Promise<string> {
    const payload = { sub: userId, ...extraPayload };
    try {
      return jwt.sign(payload, config.JWT_SECRET, { expiresIn: TOKEN_DEFAULT_EXPIRE_SECONDS });
    } catch (error: any) {
      logger.error(error, `Error signing JWT for user ID: ${userId}`);
      throw new ServerError('Could not generate authentication token.');
    }
  }

  /**
   * Invalide un token en le stockant dans Redis
   */
  async invalidateToken(token: string): Promise<void> {
    if (!redisClient) {
      logger.error('Redis unavailable for token invalidation.');
      throw new ServerError('Authentication service temporarily unavailable.');
    }
    const redisKey = this.getRedisInvalidationKey(token);
    try {
      await redisClient.setEx(redisKey, TOKEN_DEFAULT_EXPIRE_SECONDS, 'invalidated');
    } catch (error) {
      logger.error(error, `Error invalidating token: ${token.substring(0, 10)}...`);
      throw new ServerError('Error during logout.');
    }
  }

  /**
   * Vérifie si un token a été invalidé
   */
  async isTokenInvalidated(token: string): Promise<boolean> {
    if (!redisClient) {
      logger.error('Redis unavailable for token invalidation check.');
      // Fail-safe: autoriser l'accès si Redis est indisponible (politique de sécurité à définir)
      return false;
    }
    const redisKey = this.getRedisInvalidationKey(token);
    try {
      const res = await redisClient.get(redisKey);
      return !!res;
    } catch (error) {
      logger.error(error, `Error checking token invalidation: ${token.substring(0, 10)}...`);
      // Fail-safe: considérer le token comme valide si la vérification Redis échoue
      return false;
    }
  }

  /**
   * Génère un nouveau token pour un utilisateur donné
   */
  async generateTokenForUser(userId: number): Promise<{ token: string }> {
    const user = await this.usersService.findById(userId);
    const token = await this.signToken(user.id, { level: user.level, internal: user.internal });
    return { token };
  }

  /**
   * Met à jour le mot de passe expiré d'un utilisateur et renvoie un nouveau token
   */
  async updateExpiredPassword(email: string, newPassword: string): Promise<string> {
    const success = await this.passwordService.updateExpiredPassword(email, newPassword);
    if (!success) {
      throw new ServerError('Failed to update expired password');
    }

    const user = await this.usersService.findByEmailForAuth(email);
    if (!user) {
      throw new ServerError('Failed to fetch user after password update');
    }

    return await this.signToken(user.id, { level: user.level, internal: user.internal });
  }

  static getInstance(): LoginService {
    if (!instance) {
      instance = new LoginService(new UserRepository());
    }
    return instance;
  }
}
