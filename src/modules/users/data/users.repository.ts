import {
  type Repository,
  type DataSource,
  type FindOptionsWhere,
  IsNull,
  Not,
  type UpdateResult,
} from 'typeorm';

import { ServerError } from '@/common/errors/httpErrors';
import { appDataSource } from '@/database/data-source';

import { type PasswordStatus, SecurityLevel, User } from '../models/users.entity';

// Options for user search queries
interface FindUserOptions {
  where: FindOptionsWhere<User>;
  select?: (keyof User)[];
  withDeleted?: boolean;
}

// Options for listing users
interface FindAllUsersOptions {
  skip?: number;
  take?: number;
  where?: FindOptionsWhere<User>;
}

// Selectable fields for queries including the password hash
const USER_WITH_PASSWORD_FIELDS: (keyof User)[] = [
  'id',
  'uid',
  'email',
  'password',
  'firstName',
  'lastName',
  'level',
  'internal',
  'color',
  'preferences',
  'passwordUpdatedAt',
  'passwordStatus',
  'internalLevel',
  'createdAt',
  'updatedAt',
  'authorisationOverrides',
  'permissionsExpireAt',
  'isActive',
];

// Repository for handling user-related database operations
export class UserRepository {
  private readonly repository: Repository<User>;

  constructor(dataSource: DataSource = appDataSource) {
    this.repository = dataSource.getRepository(User);
  }

  /**
   * Generic method to find a single user with options.
   */
  private async findOneWithOptions(options: FindUserOptions): Promise<User | null> {
    try {
      return await this.repository.findOne({
        where: options.where,
        select: options.select,
        withDeleted: options.withDeleted,
      });
    } catch (error) {
      throw new ServerError(`Find one with options ${JSON.stringify(options.where)} ${error}`);
    }
  }

  /**
   * Finds an active user by their ID.
   */
  async findById(id: number): Promise<User | null> {
    return this.findOneWithOptions({ where: { id, deletedAt: IsNull() } });
  }

  /**
   * Finds an active user by their ID, including the password hash.
   */
  async findByIdWithPassword(id: number): Promise<User | null> {
    return this.findOneWithOptions({
      where: { id, deletedAt: IsNull() },
      select: USER_WITH_PASSWORD_FIELDS,
    });
  }

  /**
   * Finds an active user by their email (case-insensitive).
   */
  async findByEmail(email: string): Promise<User | null> {
    const normalizedEmail = email.toLowerCase().trim();
    return this.findOneWithOptions({
      where: { email: normalizedEmail, deletedAt: IsNull() },
    });
  }

  /**
   * Finds an active user by their email (case-insensitive), including the password hash.
   */
  async findByEmailWithPassword(email: string): Promise<User | null> {
    const normalizedEmail = email.toLowerCase().trim();
    return this.findOneWithOptions({
      where: { email: normalizedEmail, deletedAt: IsNull() },
      select: USER_WITH_PASSWORD_FIELDS,
    });
  }

  /**
   * Finds an active user by their UID.
   */
  async findByUid(uid: string): Promise<User | null> {
    return this.findOneWithOptions({ where: { uid, deletedAt: IsNull() } });
  }

  /**
   * Lists all active users with pagination and filtering.
   */
  async findAll(options: FindAllUsersOptions = {}): Promise<{ users: User[]; count: number }> {
    try {
      const where = { ...options.where, deletedAt: IsNull() };
      const [users, count] = await this.repository.findAndCount({
        where,
        order: { createdAt: 'DESC' },
        skip: options.skip,
        take: options.take,
      });
      return { users, count };
    } catch (error) {
      throw new ServerError(`Find all users, ${error}`);
    }
  }

  /**
   * Checks if an active user with the given email already exists (case-insensitive).
   */
  async checkEmailExists(email: string): Promise<boolean> {
    try {
      const normalizedEmail = email.toLowerCase().trim();
      return await this.repository.exists({
        where: { email: normalizedEmail, deletedAt: IsNull() },
      });
    } catch (error) {
      throw new ServerError(`Check email ${email} ${error}`);
    }
  }

  /**
   * Finds a soft-deleted user by their email (case-insensitive).
   */
  async findDeletedByEmail(email: string): Promise<User | null> {
    const normalizedEmail = email.toLowerCase().trim();
    return this.findOneWithOptions({
      where: { email: normalizedEmail, deletedAt: Not(IsNull()) },
      withDeleted: true,
    });
  }

  /**
   * Creates a new user instance (without saving).
   */
  create(dto: Partial<User>): User {
    return this.repository.create(dto);
  }

  /**
   * Saves a user entity to the database.
   * Normalizes email and validates before saving.
   */
  async save(user: User): Promise<User> {
    try {
      if (user.email) {
        user.email = user.email.toLowerCase().trim();
      }
      return await this.repository.save(user);
    } catch (error) {
      throw new ServerError(`Save user ${user.id || 'new'} ${error}`);
    }
  }

  /**
   * Updates an active user based on criteria.
   * Prevents updating sensitive fields like email, uid, password directly.
   */
  async update(
    criteria: number | FindOptionsWhere<User>,
    dto: Partial<User>,
  ): Promise<UpdateResult> {
    try {
      const where: FindOptionsWhere<User> =
        typeof criteria === 'number'
          ? { id: criteria, deletedAt: IsNull() }
          : { ...criteria, deletedAt: IsNull() };

      // Security: prevent updating sensitive fields directly via this method
      const safeDto = { ...dto };
      delete safeDto.email;
      delete safeDto.uid;
      delete safeDto.password;

      return await this.repository.update(where, safeDto);
    } catch (error) {
      throw new ServerError(`Update user with criteria ${JSON.stringify(criteria)} ${error}`);
    }
  }

  /**
   * Updates the password hash and status for an active user.
   * Also updates the passwordUpdatedAt timestamp.
   */
  async updatePasswordAndStatus(
    id: number,
    hashedPassword: string,
    status: PasswordStatus,
  ): Promise<UpdateResult> {
    try {
      return await this.repository.update(
        { id, deletedAt: IsNull() },
        {
          password: hashedPassword,
          passwordStatus: status,
          passwordUpdatedAt: new Date(),
        },
      );
    } catch (error) {
      throw new ServerError(`Update password for user ${id} ${error}`);
    }
  }

  /**
   * Updates only the password status for an active user.
   */
  async updatePasswordStatus(id: number, status: PasswordStatus): Promise<UpdateResult> {
    try {
      return await this.repository.update({ id, deletedAt: IsNull() }, { passwordStatus: status });
    } catch (error) {
      throw new ServerError(`Update password status for user ${id} ${error}`);
    }
  }

  /**
   * Soft deletes an active user by setting deletedAt and anonymizing the email.
   * Also clears authorization overrides.
   */
  async softDelete(id: number, anonymizedEmail: string): Promise<UpdateResult> {
    try {
      return await this.repository.update(
        { id, deletedAt: IsNull() },
        {
          deletedAt: new Date(),
          email: anonymizedEmail,
          authorisationOverrides: null,
          permissionsExpireAt: null,
        },
      );
    } catch (error) {
      throw new ServerError(`Soft delete user ${id} ${error}`);
    }
  }

  /**
   * Restores a soft-deleted user by setting deletedAt to null.
   */
  async restore(id: number): Promise<UpdateResult> {
    try {
      return await this.repository.restore(id);
    } catch (error) {
      throw new ServerError(`Restore user ${id} ${error}`);
    }
  }

  /**
   * Checks if an active user exists based on the given criteria.
   */
  async exists(where: FindOptionsWhere<User>): Promise<boolean> {
    try {
      return await this.repository.exists({
        where: { ...where, deletedAt: IsNull() },
      });
    } catch (error) {
      throw new ServerError(`Check existence with criteria ${JSON.stringify(where)} ${error}`);
    }
  }

  /**
   * Finds all active admin users.
   */
  async findAdmins(): Promise<User[]> {
    try {
      const { users } = await this.findAll({
        where: { level: SecurityLevel.ADMIN },
      });
      return users;
    } catch (error) {
      throw new ServerError(`Find admins ${error}`);
    }
  }
}
