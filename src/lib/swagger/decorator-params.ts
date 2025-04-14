import { MetadataStorage } from './metadata';

type ApiOptions = {
  method: 'get' | 'post' | 'put' | 'delete' | 'patch';
  path: string;
  group: string;
  name?: string;
  version?: string;
  permission?: string;
};

type ParamOptions = {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object';
  required?: boolean;
  in?: 'query' | 'path' | 'body' | 'header';
  description?: string;
  example?: any;
};

type ResponseOptions = {
  code: number;
  description: string;
  example?: any;
  schema?: any;
};

type ExampleOptions = {
  name: string;
  value: any;
  summary?: string;
  description?: string;
  statusCode?: number;
};

export function ApiParamExample(options: ExampleOptions) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    MetadataStorage.addExampleMetadata(target.constructor, propertyKey, {
      type: 'request',
      ...options,
    });
  };
}

export function ApiResponseExample(options: ExampleOptions) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    MetadataStorage.addExampleMetadata(target.constructor, propertyKey, {
      type: 'response',
      ...options,
      statusCode: options.statusCode || 200,
    });
  };
}

export function Api(options: ApiOptions) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    MetadataStorage.addRouteMetadata({
      target: target.constructor,
      method: options.method,
      path: options.path,
      handler: descriptor.value,
      group: options.group,
      name: options.name || propertyKey,
      version: options.version || '1.0.0',
      permission: options.permission,
    });
  };
}

export function ApiName(name: string) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    MetadataStorage.updateRouteMetadata(target.constructor, propertyKey, { name });
  };
}

export function ApiVersion(version: string) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    MetadataStorage.updateRouteMetadata(target.constructor, propertyKey, { version });
  };
}

export function ApiGroup(group: string) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    MetadataStorage.updateRouteMetadata(target.constructor, propertyKey, { group });
  };
}

export function ApiPermission(permission: string) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    MetadataStorage.updateRouteMetadata(target.constructor, propertyKey, { permission });
  };
}

export function ApiParam(options: ParamOptions) {
  return function (target: any, propertyKey: string, parameterIndex: number) {
    MetadataStorage.addParamMetadata(target.constructor, propertyKey, {
      ...options,
      parameterIndex,
    });
  };
}

export function ApiBody(options: Omit<ParamOptions, 'in'>) {
  return ApiParam({ ...options, in: 'body' });
}

export function ApiSuccess(options: ResponseOptions) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    MetadataStorage.addResponseMetadata(target.constructor, propertyKey, {
      ...options,
      isError: false,
    });
  };
}

export function ApiError(options: ResponseOptions) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    MetadataStorage.addResponseMetadata(target.constructor, propertyKey, {
      ...options,
      isError: true,
    });
  };
}
