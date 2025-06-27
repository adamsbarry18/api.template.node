import { type User } from '@/modules/users/models/users.entity';
import { type DataSource } from 'typeorm';

const DS_SERVICE = new WeakMap<Service, DataSource | object>();

export enum ResourcesKeys {
  USER = 'user',
  ADDRESSES = 'addresses',
  CURRENCIES = 'currencies',
  COMPANY = 'company',
  PRODUCT_CATEGORIES = 'product_categories',
  CUSTOMER_GROUPS = 'customer_groups',
  SUPPLIERS = 'suppliers',
  CUSTOMERS = 'customers',
  CUSTOMER_SHIPPING_ADDRESSES = 'customer_shipping_addresses',
  WAREHOUSES = 'warehouses',
  SHOPS = 'shops',
  PRODUCTS = 'products',
  PRODUCT_IMAGES = 'product_images',
  PRODUCT_VARIANTS = 'product_variants',
  COMPOSITE_PRODUCT_ITEMS = 'composite_product_items',
  PRODUCT_SUPPLIERS = 'product_suppliers',
  STOCK_MOVEMENTS = 'stock_movements',
  INVENTORY_SESSIONS = 'inventory_sessions',
  INVENTORY_SESSION_ITEMS = 'inventory_session_items',
  STOCK_TRANSFERS = 'stock_transfers',
  STOCK_TRANSFER_ITEMS = 'stock_transfer_items',
  PURCHASE_ORDERS = 'purchase_orders',
  PURCHASE_ORDER_ITEMS = 'purchase_order_items',
  PURCHASE_RECEPTIONS = 'purchase_receptions',
  PURCHASE_RECEPTION_ITEMS = 'purchase_reception_items',
  SUPPLIER_INVOICES = 'supplier_invoices',
  SUPPLIER_INVOICE_ITEMS = 'supplier_invoice_items',
  SUPPLIER_INVOICE_PURCHASE_ORDER_LINKS = 'supplier_invoice_purchase_order_links',
  SUPPLIER_RETURNS = 'supplier_returns',
  SUPPLIER_RETURN_ITEMS = 'supplier_return_items',
  QUOTES = 'quotes',
  QUOTE_ITEMS = 'quote_items',
  SALES_ORDERS = 'sales_orders',
  SALES_ORDER_ITEMS = 'sales_order_items',
  DELIVERIES = 'deliveries',
  DELIVERY_ITEMS = 'delivery_items',
  CUSTOMER_INVOICES = 'customer_invoices',
  CUSTOMER_INVOICE_ITEMS = 'customer_invoice_items',
  CUSTOMER_INVOICE_SALES_ORDER_LINKS = 'customer_invoice_sales_order_links',
  CUSTOMER_RETURNS = 'customer_returns',
  CUSTOMER_RETURN_ITEMS = 'customer_return_items',
  PAYMENT_METHODS = 'payment_methods',
  BANK_ACCOUNTS = 'bank_accounts',
  CASH_REGISTERS = 'cash_registers',
  CASH_REGISTER_SESSIONS = 'cash_register_sessions',
  PAYMENTS = 'payments',
  CASH_REGISTER_TRANSACTIONS = 'cash_register_transactions',
  USER_ACTIVITY_LOGS = 'user_activity_logs',
  NOTIFICATIONS = 'notifications',
  NA = 'n/a',
}

/**
 * Classe de base des services
 */
export class Service {
  entity?: string;
  private static _currentUser: User | null = null;
  // Hack to have a proper type for constructor https://github.com/microsoft/TypeScript/issues/3841
  ['constructor']!: typeof Service;

  constructor(dataSourceService: object = {}) {
    if (dataSourceService) {
      DS_SERVICE.set(this, dataSourceService);
    }
  }

  /**
   * Retourne l'objet d'accès aux données
   */
  get DataSource(): DataSource | object {
    return DS_SERVICE.get(this) as DataSource | object;
  }

  /**
   * Ready flag
   */
  static get isReady(): boolean {
    return true;
  }

  static resourceKey(): ResourcesKeys {
    return this.name as ResourcesKeys;
  }

  static setUser(user: User): void {
    Service._currentUser = user;
  }

  static getUser(): User | null {
    return Service._currentUser;
  }

  static clearUser(): void {
    Service._currentUser = null;
  }
}

export function service(registry: { entity: string }): ClassDecorator {
  return function (target: any): void {
    target.prototype.entity = registry.entity;
  };
}

export class DependentWrapper {
  resourceKey: ResourcesKeys;
  resourceName: string; // Nom de la ressource (ex: "Company", "Customer")
  resourceId: string; // ID de la ressource dépendante
  preventDeletion: boolean;

  constructor(resourceKey: ResourcesKeys, resourceId: string, preventDeletion: boolean) {
    this.resourceKey = resourceKey;
    this.resourceName = resourceKey.charAt(0).toUpperCase() + resourceKey.slice(1); // Capitalize for display
    this.resourceId = resourceId;
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
    return res as T;
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
export const deepCopy = function <T>(obj: T): T {
  if (!obj) return obj;
  if (typeof obj !== 'object' && !Array.isArray(obj)) return obj;
  return JSON.parse(JSON.stringify(obj)) as T;
};

export function isJson(str: string): boolean {
  try {
    JSON.parse(str);
  } catch {
    return false;
  }
  return true;
}
