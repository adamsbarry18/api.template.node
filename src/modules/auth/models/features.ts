import { SecurityLevel } from '@/modules/users/models/users.types';

// Interface pour la config BRUTE d'un flag
interface RawFlagConfig {
  value: number; // Puissance de 2 (1, 2, 4, 8...)
  inheritedFlags?: string[];
  level: SecurityLevel;
}

// Interface pour la config TRAITÉE d'un flag (avec masque hérité calculé)
interface ProcessedFlag {
  value: number; // Valeur brute du flag spécifique
  combinedMask: number; // Masque incluant ce flag et ceux hérités
  level: SecurityLevel;
}

// Config des features (INCHANGÉE)
export const FEATURES_CONFIG = [
  { id: 1, name: 'folder' },
  { id: 7, name: 'connect' },
  {
    id: 15,
    name: 'user',
    flags: {
      /* ... */
    } as Record<string, Partial<RawFlagConfig>>,
  },
  {
    id: 42,
    name: 'config',
    flags: {
      /* ... */
    } as Record<string, Partial<RawFlagConfig>>,
  },
  // ... etc
];

// Objets d'accès rapide (INCHANGÉS)
export const FEATURES_BY_NAME: { [key: string]: (typeof FEATURES_CONFIG)[0] } = {};
export const FEATURES_BY_ID: { [key: number]: (typeof FEATURES_CONFIG)[0] } = {};
FEATURES_CONFIG.forEach((f) => {
  FEATURES_BY_NAME[f.name] = f;
  FEATURES_BY_ID[f.id] = f;
});

// Map[featureId] -> { actionName: RawFlagConfig }
// Toujours utile pour l'encodage (connaître la valeur brute de chaque action)
export const featuresRawFlagsConfigMap = new Map<number, Record<string, RawFlagConfig>>();

// Map[featureId] -> { name: string, flags: { actionName: ProcessedFlag } }
// Contient les masques combinés pré-calculés pour la VÉRIFICATION
export const featuresProcessedFlagsMap = new Map<
  number,
  { name: string; flags: Record<string, ProcessedFlag> }
>();

// --- TRAITEMENT sans la bibliothèque `bitmask-flags` ---
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

  // Stocker la config BRUTE
  featuresRawFlagsConfigMap.set(feature.id, rawFlagsForFeature);

  // Calculer les masques combinés (logique inchangée)
  const processedFlags: Record<string, ProcessedFlag> = {};
  for (const flagName of Object.keys(rawFlagsForFeature)) {
    processedFlags[flagName] = {
      value: rawFlagsForFeature[flagName].value, // Garder la valeur brute
      combinedMask: calculateCombinedMask(flagName, rawFlagsForFeature), // Masque avec héritage
      level: rawFlagsForFeature[flagName].level,
    };
  }

  // Stocker la config TRAITÉE
  featuresProcessedFlagsMap.set(feature.id, {
    name: feature.name,
    flags: processedFlags,
  });
});

// Fonction de calcul de masque (INCHANGÉE, elle utilise déjà la logique bitwise)
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
        mask |= flag.value; // Opération OU bitwise
        stack.push(...(flag.inheritedFlags ?? []));
      }
    }
  }
  return mask;
}

// Fonction de padding (INCHANGÉE)
export const paddingLeft = (value: string, padding: string): string => {
  return (padding + value).slice(-padding.length);
};
