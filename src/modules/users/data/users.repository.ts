import { Repository, DataSource, FindOptionsWhere, IsNull, Not } from 'typeorm';
import { AppDataSource } from '@/database/data-source';
import { User } from '../models/users.entity';
import { PasswordStatus } from '../models/users.types';

export class UserRepository {
  private readonly ormRepository: Repository<User>;

  constructor(dataSource: DataSource = AppDataSource) {
    this.ormRepository = dataSource.getRepository(User);
  }

  /** Trouve un utilisateur par ID (non supprimé) */
  async findById(id: number): Promise<User | null> {
    return this.ormRepository.findOne({
      where: { id, deletedAt: IsNull() },
    });
  }

  /** Trouve un utilisateur par Email (non supprimé) */
  async findByEmail(email: string): Promise<User | null> {
    return this.ormRepository.findOne({
      where: { email: email.toLowerCase().trim(), deletedAt: IsNull() },
    });
  }

  /** Trouve un utilisateur par Email, incluant le mot de passe (non supprimé) */
  async findByEmailWithPassword(email: string): Promise<User | null> {
    return this.ormRepository.findOne({
      where: { email: email.toLowerCase().trim(), deletedAt: IsNull() },
      // TypeORM sélectionne toutes les colonnes par défaut, mais addSelect est plus explicite si nécessaire
      // addSelect: ['user.password'], // Assure que le mdp est inclus si vous avez une sélection globale qui l'exclut
    });
  }

  /** Trouve un utilisateur par UID (non supprimé) */
  async findByUid(uid: string): Promise<User | null> {
    return this.ormRepository.findOne({
      where: { uid: uid, deletedAt: IsNull() },
    });
  }

  /** Liste les utilisateurs selon des critères (ex: filtrer internes, pagination...) */
  async findAll(
    options: { skip?: number; take?: number; where?: FindOptionsWhere<User> } = {},
  ): Promise<{ users: User[]; count: number }> {
    const whereClause = { ...options.where, deletedAt: IsNull() };
    const [users, count] = await this.ormRepository.findAndCount({
      where: whereClause,
      order: { createdAt: 'DESC' },
      skip: options.skip,
      take: options.take,
    });
    return { users, count };
  }

  /** Vérifie si un email existe (non supprimé) */
  async checkEmailExists(email: string): Promise<boolean> {
    const count = await this.ormRepository.count({
      where: { email: email.toLowerCase().trim(), deletedAt: IsNull() },
    });
    return count > 0;
  }

  /** Trouve un utilisateur supprimé par email */
  async findDeletedByEmail(email: string): Promise<User | null> {
    return this.ormRepository.findOne({
      where: { email: email.toLowerCase().trim(), deletedAt: Not(IsNull()) },
      withDeleted: true,
    });
  }

  /** Crée une instance d'entité User (non persistée) */
  create(dto: Partial<User>): User {
    return this.ormRepository.create(dto);
  }

  /** Sauvegarde une entité User (insère ou met à jour) */
  async save(user: User): Promise<User> {
    return this.ormRepository.save(user);
  }

  /** Met à jour partiellement un utilisateur par ID */
  async update(id: number, dto: Partial<User>): Promise<{ affected?: number }> {
    // Supprimer les champs non modifiables directement via update (comme l'email ou l'uid)
    // delete dto.email;
    // delete dto.uid;
    return this.ormRepository.update({ id, deletedAt: IsNull() }, dto);
  }

  /** Met à jour directement le mot de passe et son statut */
  async updatePasswordAndStatus(
    id: number,
    hashedPassword: string,
    status: PasswordStatus,
  ): Promise<{ affected?: number }> {
    return this.ormRepository.update(id, {
      password: hashedPassword,
      passwordStatus: status,
      passwordUpdatedAt: new Date(),
    });
  }

  /** Met à jour uniquement le statut du mot de passe */
  async updatePasswordStatus(id: number, status: PasswordStatus): Promise<{ affected?: number }> {
    return this.ormRepository.update(id, { passwordStatus: status });
  }

  /** Supprime logiquement un utilisateur (soft delete) */
  async softDelete(id: number, anonymizedEmail: string): Promise<{ affected?: number }> {
    return this.ormRepository.update(id, {
      deletedAt: new Date(),
      email: anonymizedEmail,
      authorisationOverrides: null,
      permissionsExpireAt: null,
    });
  }

  /** Restaure un utilisateur logiquement supprimé */
  async restore(id: number): Promise<{ affected?: number }> {
    return this.ormRepository.restore(id);
  }

  // --- Ajoutez d'autres méthodes spécifiques si nécessaire ---
}
