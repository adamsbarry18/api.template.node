export enum ResourcesKeys {
  USER = 'user',
  NA = 'n/a',
}

export function service(registry: { entity: string }): ClassDecorator {
  return function (target: any): void {
    // Ajout par défaut du name
    target.prototype.entity = registry.entity;
  };
}

// Entity dependency declaration decorator
export function dependency(
  resourceKey: ResourcesKeys,
  dependencies: ResourcesKeys[] = [],
): ClassDecorator {
  if (!resourceKey) throw 'RessourceKey not defined';
  if (!Object.values(ResourcesKeys).includes(resourceKey))
    throw `RessourceKey ${resourceKey} not found`;
  return function (target: any): void {
    target.resourceKey = (): ResourcesKeys => resourceKey;
    target.dependencies = (): ResourcesKeys[] => dependencies;
  };
}

export class DependentWrapper {
  resourceKey: ResourcesKeys;
  id: string;
  preventDeletion: boolean;

  constructor(id: string, preventDeletion: boolean) {
    this.resourceKey = ResourcesKeys.NA;
    this.id = id;
    this.preventDeletion = preventDeletion;
  }
}
const pendingAsyncFunctionPromise: Map<string, Promise<any>> = new Map();

/**
 * Debounce function to avoid multiple parallel executions
 * All debounced calls will be returned the same result
 * @param key function call identifier
 * @param fn Function to debounce result from
 * @returns function result
 */
export async function debounceAsyncFunction<T>(key: string, fn: () => T): Promise<T> {
  const existingPending = pendingAsyncFunctionPromise.get(key);
  if (existingPending) {
    const res = await existingPending;
    return res;
  }
  const newPending = (async (): Promise<T> => {
    try {
      const result = await fn();
      pendingAsyncFunctionPromise.delete(key);
      return result;
    } catch (err) {
      pendingAsyncFunctionPromise.delete(key);
      throw err;
    }
  })();
  pendingAsyncFunctionPromise.set(key, newPending);
  return newPending;
}

/**
 * Copy object
 * @param obj object to copy
 * @returns return object copied
 */
export const deepCopy = function (obj: object): object {
  if (!obj) return obj;
  if (typeof obj !== 'object' && !Array.isArray(obj)) return obj;
  return JSON.parse(JSON.stringify(obj));
};

export function isJson(str: string): boolean {
  try {
    JSON.parse(str);
  } catch {
    return false;
  }
  return true;
}
