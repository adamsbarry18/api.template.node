import { SecurityLevel } from '@/modules/users/models/users.entity';

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

/**
 * Interface for the raw configuration of a flag.
 */
interface RawFlagConfig {
  value: number;
  inheritedFlags?: string[];
  level: SecurityLevel;
}

/**
 * Interface for the processed configuration of a flag.
 */
interface ProcessedFlag {
  value: number;
  combinedMask: number;
  level: SecurityLevel;
}

/**
 * The configuration for features.
 */
export const FEATURES_CONFIG = [
  { id: 1, name: 'folder' },
  {
    id: 2,
    name: 'user',
    flags: {
      read: {
        value: 1,
        level: SecurityLevel.READER,
      },
      write: {
        value: 2,
        level: SecurityLevel.ADMIN,
      },
      create: {
        value: 4,
        inheritedFlags: ['write'],
        level: SecurityLevel.ADMIN,
      },
      execute: {
        value: 8,
        level: SecurityLevel.ADMIN,
      },
    } as Record<string, Partial<RawFlagConfig>>,
  },
  // ... etc
];

// Quick access objects (UNCHANGED)
/**
 * Quick access object for features by name.
 */
export const FEATURES_BY_NAME: { [key: string]: (typeof FEATURES_CONFIG)[0] } = {};
/**
 * Quick access object for features by ID.
 */
export const FEATURES_BY_ID: { [key: number]: (typeof FEATURES_CONFIG)[0] } = {};
FEATURES_CONFIG.forEach((f) => {
  FEATURES_BY_NAME[f.name] = f;
  FEATURES_BY_ID[f.id] = f;
});

// Map[featureId] -> { actionName: RawFlagConfig }
/**
 * Map of feature ID to raw flag configurations.
 */
export const featuresRawFlagsConfigMap = new Map<number, Record<string, RawFlagConfig>>();

// Map[featureId] -> { name: string, flags: { actionName: ProcessedFlag } }
/**
 * Map of feature ID to processed flag configurations.
 */
export const featuresProcessedFlagsMap = new Map<
  number,
  { name: string; flags: Record<string, ProcessedFlag> }
>();

// --- PROCESSING without `bitmask-flags` library ---
FEATURES_CONFIG.forEach((feature) => {
  const defaultFlags: Record<string, RawFlagConfig> = {
    read: { value: 1, inheritedFlags: [], level: SecurityLevel.READER },
    write: { value: 2, inheritedFlags: ['read'], level: SecurityLevel.USER },
    create: { value: 4, inheritedFlags: ['read', 'write'], level: SecurityLevel.USER },
    execute: { value: 8, inheritedFlags: [], level: SecurityLevel.USER },
  };

  const rawFlagsForFeature: Record<string, RawFlagConfig> = {};
  const allFlagNames = new Set([
    ...Object.keys(defaultFlags),
    ...(feature.flags ? Object.keys(feature.flags) : []),
  ]);

  allFlagNames.forEach((flagName) => {
    const specificConf = feature.flags?.[flagName] ?? {};
    const defaultConf = defaultFlags[flagName];
    if (defaultConf) {
      rawFlagsForFeature[flagName] = {
        value: specificConf.value ?? defaultConf.value,
        inheritedFlags: specificConf.inheritedFlags ?? defaultConf.inheritedFlags ?? [],
        level: specificConf.level ?? defaultConf.level,
      };
    } else if (specificConf.value !== undefined && specificConf.level !== undefined) {
      rawFlagsForFeature[flagName] = {
        value: specificConf.value,
        inheritedFlags: specificConf.inheritedFlags ?? [],
        level: specificConf.level,
      };
    }
  });

  // Store raw configuration
  featuresRawFlagsConfigMap.set(feature.id, rawFlagsForFeature);

  // Calculate combined masks (unchanged logic)
  const processedFlags: Record<string, ProcessedFlag> = {};
  for (const flagName of Object.keys(rawFlagsForFeature)) {
    processedFlags[flagName] = {
      value: rawFlagsForFeature[flagName].value,
      combinedMask: calculateCombinedMask(flagName, rawFlagsForFeature),
      level: rawFlagsForFeature[flagName].level,
    };
  }

  // Store processed configuration
  featuresProcessedFlagsMap.set(feature.id, {
    name: feature.name,
    flags: processedFlags,
  });
});

/**
 * Calculates the combined mask for a given flag.
 * @param flagName The name of the flag.
 * @param flags The flag configurations.
 * @returns The combined mask.
 */
function calculateCombinedMask(flagName: string, flags: Record<string, RawFlagConfig>): number {
  const visited = new Set<string>();
  const stack: string[] = [flagName];
  let mask = 0;
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (!visited.has(current)) {
      visited.add(current);
      const flag = flags[current];
      if (flag) {
        mask |= flag.value;
        stack.push(...(flag.inheritedFlags ?? []));
      }
    }
  }
  return mask;
}

/**
 * Pads a string with a given padding.
 * @param value The string to pad.
 * @param padding The padding string.
 * @returns The padded string.
 */
export const paddingLeft = (value: string, padding: string): string => {
  return (padding + value).slice(-padding.length);
};
