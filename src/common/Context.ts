export interface IContext {
  token?: string;
  internal: boolean;
  display?: string;
  siteId?: string;
  language?: string;
  version?: number;
  translate?: boolean;
  filter?: any;
  userId?: number;
  env?: string;
}

export class Context {
  userId?: number;
  siteId?: string;
  token?: string;
  internal: boolean = false;
  translate: boolean = true;
  display: string = '';
  env: string = '';
  filter?: any = null;
  language?: string = 'en';
  INSTANCE_WK = new WeakMap();
  translations = {};

  constructor(params: IContext) {
    if (params.siteId) {
      this.siteId = params.siteId;
    }
    if (params.language && params.language.length >= 2) {
      this.language = params.language.substr(0, 2);
    }
    if (params.filter) {
      this.filter = params.filter;
    }

    if (params.userId) {
      this.userId = params.userId;
    }

    if (params.token) {
      this.token = params.token;
    }

    if (params.translate !== undefined) {
      this.translate = params.translate;
    }

    if (params.hasOwnProperty('internal')) {
      this.internal = params.internal;
    }
  }

  clone(newCtx: Context): Context {
    return new Context(Object.assign({}, this, newCtx));
  }
}
