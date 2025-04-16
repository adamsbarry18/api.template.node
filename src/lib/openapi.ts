import swaggerJsdoc, { Options, SwaggerDefinition } from 'swagger-jsdoc';
import path from 'path';
import config from '@/config';
import logger from './logger';

let apiVersion = '1.0.0';
try {
  const pkg = require(path.resolve(process.cwd(), 'package.json'));
  if (pkg && pkg.version) {
    apiVersion = pkg.version;
  }
} catch (error) {
  logger.warn('Impossible de lire la version depuis package.json pour Swagger.');
}
// Configuration des options pour swagger-jsdoc
const options: Options = {
  // Définition de la spécification OpenAPI 3.0
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Mon API Backend',
      version: apiVersion,
      description: "Documentation de l'API pour le projet backend.",
      contact: {
        name: 'Équipe de Développement',
        // Vous pouvez ajouter url et email si nécessaire :
        // url: 'https://votresite.com/support',
        // email: 'contact@votredomaine.com',
      },
      // license: {
      //   name: 'MIT',
      //   url: 'https://opensource.org/licenses/MIT',
      // },
    },
    // Serveurs de l'API
    servers: [
      {
        url: `${config.API_URL || `http://localhost:${config.PORT}`}/api/v1`, // Base path inclus (/api/v1)
        description: `Serveur ${config.NODE_ENV}`,
      },
      // Vous pouvez ajouter d'autres serveurs (staging, production) ici
      // { url: 'https://staging.votredomaine.com/api/v1', description: 'Serveur Staging' },
      // { url: 'https://api.votredomaine.com/api/v1', description: 'Serveur Production' },
    ],
    // Composants réutilisables (schémas, sécurité, etc.)
    components: {
      /*Schéma de sécurité pour l'authentification JWT Bearer
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Entrez votre token JWT précédé de "Bearer " (ex: Bearer eyJ...)',
        },
      },*/
      // Définition des schémas réutilisables (réponses d'erreur, pagination, etc.)
      schemas: {
        ErrorResponse: {
          type: 'object',
          properties: {
            success: {
              type: 'boolean',
              example: false,
              description: "Indique si l'opération a échoué",
            },
            message: {
              type: 'string',
              description: "Message d'erreur lisible par l'humain",
            },
            code: {
              type: 'string',
              description: "Code d'erreur applicatif unique (optionnel)",
              example: 'ERR_NOT_FOUND',
            },
            // Vous pouvez ajouter d'autres propriétés comme `data` ou `stack` selon vos besoins
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
        // Ajoutez d'autres schémas réutilisables ici
      },
      // Vous pouvez également définir ici des paramètres ou réponses communs
    },
    // Appliquer la sécurité JWT Bearer par défaut à toutes les routes
    // Pour rendre une route publique, ajoutez l’annotation JSDoc @security [] dans sa documentation.
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  // Chemins vers les fichiers où se trouvent vos annotations JSDoc pour Swagger
  apis: [
    // Par convention, on scanne les fichiers de route dans le dossier src/modules
    path.resolve(process.cwd(), 'src/modules/**/*.routes.ts'),
  ],
};
//
// Génération de la spécification Swagger
//
let swaggerSpec: SwaggerDefinition | null = null;
try {
  const generatedSpec = swaggerJsdoc(options) as SwaggerDefinition;
  if (!generatedSpec) {
    throw new Error('La génération de la spécification Swagger a retourné undefined.');
  }

  if (!generatedSpec.paths || Object.keys(generatedSpec.paths).length === 0) {
    logger.warn(
      'La spécification Swagger a été générée, mais aucun chemin n’a été trouvé. Vérifiez les annotations JSDoc et le chemin défini dans `apis`.',
    );
  } else {
    const pathCount = Object.keys(generatedSpec.paths).length;
    logger.info(`Spécification Swagger générée avec succès (${pathCount} chemin(s) trouvé(s)).`);
  }
  swaggerSpec = generatedSpec;
} catch (error: any) {
  logger.error(error, 'Échec de la génération de la spécification Swagger');
  // En cas d'erreur, retourne une spécification de secours
  swaggerSpec = {
    openapi: '3.0.0',
    info: { title: 'API Docs (Erreur de génération)', version: apiVersion },
    paths: {},
    servers: options.definition?.servers ?? [],
  };
}
export default swaggerSpec;
