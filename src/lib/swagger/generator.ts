import { MetadataStorage } from './metadata';
import { SwaggerDefinition } from 'swagger-jsdoc';

export class SwaggerGenerator {
  static generate(baseConfig: SwaggerDefinition): SwaggerDefinition {
    const { routes, params, responses, examples } = MetadataStorage.getMetadata();

    return {
      ...baseConfig,
      paths: this.generatePaths(routes, params, responses, examples),
      components: {
        ...baseConfig.components,
        schemas: {
          ...baseConfig.components?.schemas,
          ...this.generateSchemas(),
        },
        examples: {
          ...baseConfig.components?.examples,
          ...this.generateExamples(examples),
        },
      },
    };
  }

  private static generatePaths(
    routes: any[],
    params: Map<string, any>,
    responses: Map<string, any>,
    examples: Map<string, any>,
  ) {
    return routes.reduce((acc, route) => {
      const pathKey = route.path;
      const method = route.method.toLowerCase();
      const routeKey = `${route.target.name}-${route.handler.name}`;

      acc[pathKey] = {
        ...acc[pathKey],
        [method]: {
          tags: [route.group],
          summary: route.name,
          description: route.description,
          security: route.security || [],
          parameters: this.getParameters(params.get(routeKey)),
          requestBody: this.getRequestBody(examples.get(routeKey)),
          responses: this.getResponses(responses.get(routeKey)),
        },
      };
      return acc;
    }, {});
  }

  private static generateSchemas() {
    // Implémentez la génération des schémas personnalisés si nécessaire
    return {};
  }

  private static generateExamples(examplesMap: Map<string, any>) {
    const examples: Record<string, any> = {};

    examplesMap.forEach((ex, key) => {
      examples[key] = ex.reduce((acc: any, curr: any) => {
        acc[curr.name] = {
          summary: curr.summary,
          description: curr.description,
          value: curr.value,
        };
        return acc;
      }, {});
    });

    return examples;
  }

  private static getParameters(routeParams: any[] = []) {
    return routeParams.map((param) => ({
      name: param.name,
      in: param.in,
      description: param.description,
      required: param.required,
      schema: { type: param.type },
      example: param.example,
    }));
  }

  private static getRequestBody(routeExamples: any[] = []) {
    if (routeExamples.length === 0) return undefined;

    return {
      content: {
        'application/json': {
          examples: routeExamples.reduce((acc, example) => {
            acc[example.name] = { value: example.value };
            return acc;
          }, {}),
        },
      },
    };
  }

  private static getResponses(routeResponses: any[] = []) {
    return routeResponses.reduce((acc, response) => {
      acc[response.code] = {
        description: response.description,
        content: {
          'application/json': {
            schema: response.schema || { type: 'object' },
            example: response.example,
          },
        },
      };
      return acc;
    }, {});
  }
}
