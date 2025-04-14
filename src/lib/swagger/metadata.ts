export class MetadataStorage {
  private static instance: MetadataStorage;
  private routes: any[] = [];
  private params: Map<string, any[]> = new Map();
  private responses: Map<string, any[]> = new Map();

  static addRouteMetadata(metadata: any) {
    this.getInstance().routes.push(metadata);
  }

  private examples: Map<string, any[]> = new Map();

  static addExampleMetadata(target: any, propertyKey: string, example: any) {
    const key = `${target.name}-${propertyKey}`;
    const examples = this.getInstance().examples.get(key) || [];
    examples.push(example);
    this.getInstance().examples.set(key, examples);
  }

  static updateRouteMetadata(target: any, propertyKey: string, updates: any) {
    const route = this.getInstance().routes.find(
      (r) => r.target === target && r.handler.name === propertyKey,
    );
    if (route) Object.assign(route, updates);
  }

  static addParamMetadata(target: any, propertyKey: string, param: any) {
    const key = `${target.name}-${propertyKey}`;
    const params = this.getInstance().params.get(key) || [];
    params.push(param);
    this.getInstance().params.set(key, params);
  }

  static addResponseMetadata(target: any, propertyKey: string, response: any) {
    const key = `${target.name}-${propertyKey}`;
    const responses = this.getInstance().responses.get(key) || [];
    responses.push(response);
    this.getInstance().responses.set(key, responses);
  }

  static getMetadata() {
    return {
      routes: this.getInstance().routes,
      params: this.getInstance().params,
      responses: this.getInstance().responses,
      examples: this.getInstance().examples,
    };
  }

  private static getInstance() {
    if (!this.instance) this.instance = new MetadataStorage();
    return this.instance;
  }
}
