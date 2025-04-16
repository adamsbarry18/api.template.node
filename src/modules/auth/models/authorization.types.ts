/**
 * Map of feature names to allowed action names.
 * Example: { user: ['read', 'write'], config: ['read'] }
 */
export type PermissionsInputMap = Record<string, string[]>;

/**
 * Effective and decoded authorisations for a user.
 * Combines base level and overrides, considering expiry.
 */
export interface DecodedAuthorisations {
  userId: number;
  level: number;
  expiresAt: Date | null;
  permissions: Record<
    string,
    {
      id: number;
      actions: string[];
    }
  >;
}
