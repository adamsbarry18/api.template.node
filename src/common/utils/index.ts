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

export enum SORT_TYPE {
  FROM_COLUMN = 'FROM_COLUMN',
  COMPUTED = 'COMPUTED',
}

export enum SORT_DIRECTION {
  ASC = 'asc',
  DESC = 'desc',
}

export enum FILTER_TYPE {
  FROM_COLUMN = 'FROM_COLUMN',
  COMPUTED = 'COMPUTED',
}

export enum FILTER_OPERATOR {
  EQ = 'eq',
  LT = 'lt',
  LTE = 'lte',
  GT = 'gt',
  GTE = 'gte',
  IN = 'in',
  CONTAINS = 'contains',
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
  } catch (e) {
    return false;
  }
  return true;
}
