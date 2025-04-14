import { Repository, DataSource, FindOptionsWhere, IsNull, Not, UpdateResult } from 'typeorm';
import { AppDataSource } from '@/database/data-source';
import { User } from '../models/users.entity';
import { PasswordStatus, SecurityLevel } from '../models/users.types';

/**
 * Repository pour l'entité User.
 * Encapsule toutes les interactions avec la base de données pour les utilisateurs,
 * en utilisant TypeORM.
 */
export class UserRepository {
  private readonly ormRepository: Repository<User>;

  /**
   * Crée une instance de UserRepository.
   * @param dataSource - L'instance DataSource TypeORM. Par défaut, utilise AppDataSource globale.
   * Permet l'injection de dépendances pour les tests.
   */
  constructor(dataSource: DataSource = AppDataSource) {
    this.ormRepository = dataSource.getRepository(User);
  }

  /**
   * Trouve un utilisateur actif par son ID numérique.
   * @param id - L'ID de l'utilisateur.
   * @returns L'entité User trouvée ou null.
   */
  async findById(id: number): Promise<User | null> {
    return this.ormRepository.findOne({
      where: {
        id,
        deletedAt: IsNull(),
      },
    });
  }

  /**
   * Trouve un utilisateur actif par son ID, incluant le mot de passe.
   * Utile pour la vérification lors de la mise à jour du mot de passe.
   * @param id - L'ID de l'utilisateur.
   * @returns L'entité User trouvée avec le mot de passe, ou null.
   */
  async findByIdWithPassword(id: number): Promise<User | null> {
    return this.ormRepository.findOne({
      where: { id, deletedAt: IsNull() },
      select: [
        'id',
        'uid',
        'email',
        'name',
        'surname',
        'level',
        'internal',
        'language',
        'color',
        'preferences',
        'passwordUpdatedAt',
        'passwordStatus',
        'internalLevel',
        'createdAt',
        'updatedAt',
        'authorisationOverrides',
        'permissionsExpireAt',
        'password',
      ],
    });
  }

  /**
   * Trouve un utilisateur actif par son adresse email (insensible à la casse).
   * @param email - L'adresse email de l'utilisateur.
   * @returns L'entité User trouvée ou null.
   */
  async findByEmail(email: string): Promise<User | null> {
    return this.ormRepository.findOne({
      where: {
        email: email.toLowerCase().trim(),
        deletedAt: IsNull(),
      },
    });
  }

  /**
   * Trouve un utilisateur actif par son adresse email, incluant le mot de passe.
   * Utilisé principalement pour l'authentification (login).
   * @param email - L'adresse email de l'utilisateur.
   * @returns L'entité User complète (avec mot de passe) ou null.
   */
  async findByEmailWithPassword(email: string): Promise<User | null> {
    return this.ormRepository.findOne({
      where: {
        email: email.toLowerCase().trim(),
        deletedAt: IsNull(),
      },
    });
  }

  /**
   * Trouve un utilisateur actif par son UID.
   * @param uid - L'identifiant unique (UUID) de l'utilisateur.
   * @returns L'entité User trouvée ou null.
   */
  async findByUid(uid: string): Promise<User | null> {
    return this.ormRepository.findOne({
      where: { uid: uid, deletedAt: IsNull() },
    });
  }

  /**
   * Récupère une liste d'utilisateurs actifs avec pagination et filtrage optionnels.
   * @param options - Options de pagination (skip, take) et de filtrage (where).
   * @returns Un objet contenant la liste des utilisateurs et le nombre total correspondant aux critères.
   */
  async findAll(
    options: { skip?: number; take?: number; where?: FindOptionsWhere<User> } = {},
  ): Promise<{ users: User[]; count: number }> {
    const whereClause = { ...options.where, deletedAt: IsNull() };

    const [users, count] = await this.ormRepository.findAndCount({
      where: whereClause,
      order: { createdAt: 'DESC' }, // Tri par défaut
      skip: options.skip,
      take: options.take,
    });
    return { users, count };
  }

  /**
   * Vérifie si un utilisateur actif existe avec l'adresse email donnée.
   * @param email - L'adresse email à vérifier.
   * @returns True si l'email existe pour un utilisateur actif, false sinon.
   */
  async checkEmailExists(email: string): Promise<boolean> {
    return this.ormRepository.exists({
      where: {
        email: email.toLowerCase().trim(),
        deletedAt: IsNull(),
      },
    });
  }

  /**
   * Trouve un utilisateur spécifiquement marqué comme supprimé par son email.
   * Utile pour la réactivation de compte.
   * @param email - L'adresse email de l'utilisateur supprimé.
   * @returns L'entité User supprimée ou null.
   */
  async findDeletedByEmail(email: string): Promise<User | null> {
    return this.ormRepository.findOne({
      where: {
        email: email.toLowerCase().trim(),
        deletedAt: Not(IsNull()),
      },
      withDeleted: true,
    });
  }

  /**
   * Crée une instance de l'entité User (en mémoire, non persistée).
   * @param dto - Données initiales pour l'utilisateur.
   * @returns Une nouvelle instance de User.
   */
  create(dto: Partial<User>): User {
    return this.ormRepository.create(dto);
  }

  /**
   * Sauvegarde une entité User en base de données.
   * Gère l'insertion (si l'entité est nouvelle) ou la mise à jour (si l'entité a un ID).
   * @param user - L'entité User à sauvegarder.
   * @returns L'entité User sauvegardée (avec ID mis à jour si insertion).
   */
  async save(user: User): Promise<User> {
    return this.ormRepository.save(user);
  }

  /**
   * Met à jour partiellement un ou plusieurs utilisateurs actifs correspondant aux critères.
   * Utilise `update` de TypeORM pour l'efficacité (n'exécute qu'une seule requête UPDATE).
   * Ne déclenche pas les décorateurs d'entité comme @BeforeUpdate.
   * @param criteria - Critères pour trouver les utilisateurs à mettre à jour (ex: { id }). Inclut implicitement `deletedAt: IsNull()`.
   * @param dto - Les champs à mettre à jour.
   * @returns Un objet UpdateResult contenant le nombre de lignes affectées.
   */
  async update(
    criteria: number | FindOptionsWhere<User>,
    dto: Partial<User>,
  ): Promise<UpdateResult> {
    const whereCriteria: FindOptionsWhere<User> =
      typeof criteria === 'number'
        ? { id: criteria, deletedAt: IsNull() }
        : { ...criteria, deletedAt: IsNull() };

    delete dto.email;
    delete dto.uid;
    delete dto.password;

    return this.ormRepository.update(whereCriteria, dto);
  }

  /**
   * Met à jour spécifiquement le mot de passe, son statut et sa date de mise à jour pour un utilisateur actif.
   * @param id - L'ID de l'utilisateur.
   * @param hashedPassword - Le nouveau mot de passe déjà haché.
   * @param status - Le nouveau statut du mot de passe.
   * @returns Un objet UpdateResult.
   */
  async updatePasswordAndStatus(
    id: number,
    hashedPassword: string,
    status: PasswordStatus,
  ): Promise<UpdateResult> {
    return this.ormRepository.update(
      { id, deletedAt: IsNull() },
      {
        password: hashedPassword,
        passwordStatus: status,
        passwordUpdatedAt: new Date(),
      },
    );
  }

  /**
   * Met à jour uniquement le statut du mot de passe pour un utilisateur actif.
   * @param id - L'ID de l'utilisateur.
   * @param status - Le nouveau statut.
   * @returns Un objet UpdateResult.
   */
  async updatePasswordStatus(id: number, status: PasswordStatus): Promise<UpdateResult> {
    return this.ormRepository.update({ id, deletedAt: IsNull() }, { passwordStatus: status });
  }

  /**
   * Supprime logiquement un utilisateur (soft delete).
   * Anonymise l'email et supprime les overrides de permissions.
   * @param id - L'ID de l'utilisateur à supprimer.
   * @param anonymizedEmail - L'email anonymisé à utiliser.
   * @returns Un objet UpdateResult.
   */
  async softDelete(id: number, anonymizedEmail: string): Promise<UpdateResult> {
    return this.ormRepository.update(
      { id, deletedAt: IsNull() },
      {
        deletedAt: new Date(),
        email: anonymizedEmail,
        authorisationOverrides: null,
        permissionsExpireAt: null,
      },
    );
  }

  /**
   * Restaure un utilisateur logiquement supprimé (annule le soft delete).
   * @param id - L'ID de l'utilisateur à restaurer.
   * @returns Un objet UpdateResult.
   */
  async restore(id: number): Promise<UpdateResult> {
    return this.ormRepository.restore(id);
  }

  /**
   * Vérifie l'existence d'un utilisateur actif par ses critères.
   * @param where - Critères de recherche TypeORM.
   * @returns True si un utilisateur actif correspond, false sinon.
   */
  async exists(where: FindOptionsWhere<User>): Promise<boolean> {
    return this.ormRepository.exists({ where: { ...where, deletedAt: IsNull() } });
  }

  async findAdmins(): Promise<User[]> {
    const { users } = await this.findAll({ where: { level: SecurityLevel.ADMIN } });
    return users;
  }
}
