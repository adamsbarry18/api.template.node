import path from 'path';

import swaggerJSDoc from 'swagger-jsdoc';

import config from '@/config';
import { authSchemas, authorizationSchemas, userSchemas } from './openapi-schemas/users';


const swaggerDefinition = {
  openapi: '3.0.3',
  info: {
    title: 'API Documentation',
    version: '1.0.0',
    description: 'Documentation auto-générée de l’API',
  },
  servers: [
    {
      url: `${config.API_URL || `http://localhost:${config.PORT}`}/api/v1`,
      description: `Serveur ${config.NODE_ENV}`,
    },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
    schemas: {
      ...userSchemas,
      ...authSchemas,
      ...authorizationSchemas,
      ErrorResponse: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: false,
            description: 'Indicates if the operation failed',
          },
          message: { type: 'string', description: 'Human-readable error message' },
          code: {
            type: 'string',
            description: 'Unique application error code',
            example: 'ERR_NOT_FOUND',
          },
          data: { type: 'object', nullable: true, description: 'Optional additional error data' },
        },
        required: ['success', 'message'],
      },
    },
    responses: {
      BadRequest: {
        description: 'Bad Request',
        content: {
          'applicationJson': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              message: 'Bad Request',
              code: 'ERR_BAD_REQUEST',
            },
          },
        },
      },
      ValidationError: {
        description: 'Validation Failed',
        content: {
          'applicationJson': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              message: 'Validation Failed',
              code: 'ERR_VALIDATION',
              data: { errors: [{ field: 'email', message: 'Invalid email' }] },
            },
          },
        },
      },
      Unauthorized: {
        description: 'Unauthorized',
        content: {
          'applicationJson': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              message: 'Unauthorized',
              code: 'ERR_UNAUTHORIZED',
            },
          },
        },
      },
      Forbidden: {
        description: 'Forbidden',
        content: {
          'applicationJson': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              message: 'Forbidden',
              code: 'ERR_FORBIDDEN',
            },
          },
        },
      },
      NotFound: {
        description: 'Not Found',
        content: {
          'applicationJson': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              message: 'Not Found',
              code: 'ERR_NOT_FOUND',
            },
          },
        },
      },
      Conflict: {
        description: 'Conflict',
        content: {
          'applicationJson': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              message: 'Conflict',
              code: 'ERR_CONFLICT',
            },
          },
        },
      },
      InternalServerError: {
        description: 'Internal Server Error',
        content: {
          'applicationJson': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              message: 'Internal Server Error',
              code: 'ERR_INTERNAL_SERVER',
            },
          },
        },
      },
      ServiceUnavailable: {
        description: 'Service Unavailable',
        content: {
          'applicationJson': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              message: 'Service Unavailable',
              code: 'ERR_SERVICE_UNAVAILABLE',
            },
          },
        },
      },
    },
  },
  security: [{ bearerAuth: [] }],
};

const options = {
  swaggerDefinition,
  apis: [path.resolve(process.cwd(), 'src/modules/**/*.routes.ts')],
};

const swaggerSpec = swaggerJSDoc(options);

export default swaggerSpec;
