import path from 'path';
import config from '@/config';
import logger from '../logger';
import { SwaggerGenerator } from './generator';

let apiVersion = '1.0.0';

try {
  const pkg = require(path.resolve(process.cwd(), 'package.json'));
  if (pkg?.version) apiVersion = pkg.version;
} catch (error) {
  logger.warn('Impossible de lire la version depuis package.json pour Swagger.');
}

// Configuration de base statique
const baseOpenAPIConfig = {
  openapi: '3.0.0',
  info: {
    title: 'Mon API Backend',
    version: apiVersion,
    description: "Documentation de l'API pour le projet backend.",
    contact: { name: 'Équipe de Développement' },
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
        description: 'Token JWT précédé de "Bearer " (ex: Bearer eyJ...)',
      },
    },
    schemas: {
      ErrorResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: false },
          message: { type: 'string' },
          code: { type: 'string', nullable: true },
        },
        required: ['success', 'message'],
      },
      PaginationMeta: {
        type: 'object',
        properties: {
          currentPage: { type: 'integer', example: 1 },
          pageSize: { type: 'integer', example: 10 },
          totalItems: { type: 'integer', example: 153 },
          totalPages: { type: 'integer', example: 16 },
        },
      },
    },
    responses: {
      Unauthorized: { $ref: '#/components/schemas/ErrorResponse' },
      NotFound: { $ref: '#/components/schemas/ErrorResponse' },
      InternalServerError: { $ref: '#/components/schemas/ErrorResponse' },
    },
  },
  security: [{ bearerAuth: [] }],
};

// Génération dynamique avec les décorateurs
function generateDynamicSpec() {
  try {
    const generatedSpec = SwaggerGenerator.generate(baseOpenAPIConfig);

    return {
      ...baseOpenAPIConfig,
      paths: generatedSpec.paths,
      components: {
        ...baseOpenAPIConfig.components,
        ...generatedSpec.components,
      },
    };
  } catch (error) {
    logger.error('Erreur lors de la génération dynamique Swagger:', error);
    return {
      ...baseOpenAPIConfig,
      paths: {},
      info: {
        ...baseOpenAPIConfig.info,
        title: 'API Docs (Erreur de génération)',
      },
    };
  }
}

// Export final
export default (() => {
  try {
    const swaggerSpec = generateDynamicSpec();

    if (!swaggerSpec.paths || Object.keys(swaggerSpec.paths).length === 0) {
      logger.warn('Aucun endpoint trouvé dans la documentation Swagger');
    } else {
      logger.info(
        `Documentation Swagger générée avec ${Object.keys(swaggerSpec.paths).length} endpoints`,
      );
    }

    return swaggerSpec;
  } catch (error) {
    logger.error('Échec critique de génération Swagger:', error);
    return {
      ...baseOpenAPIConfig,
      paths: {},
      info: {
        ...baseOpenAPIConfig.info,
        title: 'API Docs (Erreur critique)',
      },
    };
  }
})();
