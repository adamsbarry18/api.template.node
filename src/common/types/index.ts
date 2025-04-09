/* eslint-disable @typescript-eslint/no-explicit-any */

interface IConfigurable {
  configure: (config: object) => void;
}

declare module 'commons/utils' {
  export const logger: (namespace: string) => ClassDecorator;
  export const log: (namespace: string) => ILogger;
  export const tryParse: (data: object | string | number) => any;
  export const prometheus: IPrometheus;
  export const mail: IMail;
  export const EventEmitter: IEventEmitter;

  interface IPrometheus extends IConfigurable {
    metrics: any;
  }

  interface IMail extends IConfigurable {
    send: (options: {
      to: string;
      subject: string;
      template: string;
      params?: { [key: string]: string };
    }) => Promise<void>;
    hasTemplate: (name: string) => boolean;
    loadTemplate: (name: string, path: string) => Promise<void>;
  }

  // eslint-disable-next-line @typescript-eslint/consistent-type-imports
  type EventEmitter = import('node:events').EventEmitter;
  interface IEventEmitter extends EventEmitter {
    // eslint-disable-next-line @typescript-eslint/no-misused-new
    new (): IEventEmitter;
  }

  export interface ILogger extends IConfigurable {
    info: (message?: any, ...optionalParams: any[]) => void;
    log: (message?: any, ...optionalParams: any[]) => void;
    debug: (message?: any, ...optionalParams: any[]) => void;
    error: (message?: any, ...optionalParams: any[]) => void;
  }
}

declare module 'commons/data' {
  export const redis: IRedisService;
  export const mysql: IMySqlService;
  export const backend: IBackEndRootServer;

  export interface IDataService extends IConfigurable {
    isConnected: () => boolean;
    events: any;
  }

  export interface IMySqlService extends IDataService {
    query: (
      query: string,
      values?: (string | number | undefined | null)[],
      options?: object,
    ) => Promise<any>;
    insert: (table: string, values: object) => Promise<{ insertId: number }>;
    update: (table: string, where: object, values: object) => Promise<{ affectedRows: number }>;
    updateById: (
      table: string,
      formatId: string,
      id: string | number,
      values: object,
    ) => Promise<{ affectedRows: number }>;
    remove: (table: string, where: object) => Promise<object>;
    removeById: (table: string, formatId: string, id: string | number) => Promise<object>;
  }

  export interface IRedisService extends IDataService {
    get: (key: string, callback?: (err: object, value: object) => void | object) => Promise<string>;
    setex: (
      key: string,
      expire: number,
      value: string | number | object,
      fn?: any,
    ) => Promise<void>;
    del: (key: string, pattern?: boolean) => void;
    publish: (channel: string, message: string | object) => void;
    on: (event: string, cb: () => void) => void;
    onMessage: (name: string, cb: (channel: string, data: object) => void) => void;
    onMessagePattern: (pattern: string, cb: (channel: string, data: object) => void) => void;
  }

  export interface IBackEndServer extends IConfigurable {
    isAvailable: () => boolean;
    disconnect: (options?: object) => void;
    send: (channel: string, event: object) => Promise<any>;
    queues: { [queue: string]: string };
  }

  interface IBackEndRootServer extends IBackEndServer {
    init: (server: string) => IBackEndServer;
  }
}
