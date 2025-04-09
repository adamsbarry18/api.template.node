// src/lib/swagger.ts
import swaggerJsdoc, { Options, SwaggerDefinition } from 'swagger-jsdoc';
import path from 'path';
import config from '@/config'; // Utilise l'alias pour la configuration
import logger from './logger'; // Logger Pino local (dans src/lib)

// Récupérer la version depuis package.json (optionnel mais propre)
let apiVersion = '1.0.0'; // Version par défaut
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const pkg = require(path.resolve(process.cwd(), 'package.json'));
  if (pkg && pkg.version) {
    apiVersion = pkg.version;
  }
} catch (error) {
  logger.warn('Could not read version from package.json for Swagger info.');
}

// Options pour swagger-jsdoc
const options: Options = {
  // Définition de base de la spécification OpenAPI 3.0
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Mon API Backend', // Adaptez le titre si nécessaire
      version: apiVersion,
      description: "Documentation de l'API pour le projet backend.", // Adaptez la description
      contact: {
        name: 'Équipe de Développement',
        // url: 'URL du site de support',
        // email: 'contact@mondomaine.com',
      },
      // license: { // Ajoutez une licence si applicable
      //   name: 'MIT',
      //   url: 'https://opensource.org/licenses/MIT',
      // },
    },
    // Définition des serveurs où l'API est hébergée
    servers: [
      {
        // Utilise l'URL de l'API depuis la config ou construit une URL locale par défaut
        url: `${config.API_URL || `http://localhost:${config.PORT}`}/api/v1`, // Inclut le base path /api/v1
        description: `Serveur ${config.NODE_ENV}`,
      },
      // Ajoutez ici d'autres serveurs (staging, production) si nécessaire
      // { url: 'https://staging.mondomaine.com/api/v1', description: 'Serveur Staging' },
      // { url: 'https://api.mondomaine.com/api/v1', description: 'Serveur Production' },
    ],
    // Définition des composants réutilisables (schémas, sécurité)
    components: {
      // Schéma de sécurité pour l'authentification JWT Bearer
      securitySchemes: {
        bearerAuth: {
          type: 'http', // Type HTTP pour l'authentification
          scheme: 'bearer', // Schéma Bearer
          bearerFormat: 'JWT', // Format du token
          description: 'Entrez votre token JWT précédé de "Bearer " (ex: Bearer eyJ...)',
        },
        // Ajoutez d'autres schémas de sécurité si nécessaire (ex: apiKey)
        // apiKeyAuth: {
        //   type: 'apiKey',
        //   in: 'header', // ou 'query' ou 'cookie'
        //   name: 'X-API-KEY',
        // },
      },
      // Schémas de données réutilisables (DTOs, modèles de réponse/erreur)
      schemas: {
        // Exemple de schéma pour une réponse d'erreur standard
        ErrorResponse: {
          type: 'object',
          properties: {
            success: {
              type: 'boolean',
              example: false,
              description: "Indique si l'opération a échoué",
            },
            message: { type: 'string', description: "Message d'erreur lisible par l'humain" },
            code: {
              type: 'string',
              description: "Code d'erreur applicatif unique (optionnel)",
              example: 'ERR_NOT_FOUND',
            },
            // data: { type: 'object', nullable: true, description: "Données supplémentaires sur l'erreur (ex: détails de validation)" },
            // stack: { type: 'string', nullable: true, description: "Stack trace (uniquement en environnement de développement)" },
          },
          required: ['success', 'message'],
        },
        // Exemple de schéma pour la pagination (utilisé dans les réponses de liste)
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
        // Vous pouvez aussi définir des schémas directement via JSDoc dans vos fichiers .ts
      },
      // Vous pouvez aussi définir des paramètres, des réponses, etc. réutilisables ici
      // parameters: { ... },
      // responses: { ... }
    },
    // Applique la sécurité JWT Bearer à toutes les routes par défaut
    // Pour rendre une route publique, ajoutez le tag JSDoc `@security []` à sa définition
    security: [
      {
        bearerAuth: [], // Référence le schéma 'bearerAuth' défini ci-dessus
      },
    ],
    // Optionnel: Définir des tags pour organiser les routes dans Swagger UI
    tags: [
      { name: 'Auth', description: "Opérations liées à l'authentification" },
      { name: 'Users', description: 'Gestion des utilisateurs' },
      // Ajoutez d'autres tags pour vos modules
      // { name: 'Products', description: 'Gestion des produits' },
    ],
  },
  // Chemins vers les fichiers contenant les annotations JSDoc
  // Utiliser path.resolve pour des chemins plus robustes
  apis: [
    // Chemin vers les contrôleurs (si vous utilisez les décorateurs et JSDoc sur les méthodes)
    path.resolve(process.cwd(), 'src/modules/**/*.controller.ts'),
    // Chemin vers les fichiers de routes (si vous utilisez des routeurs Express standard et JSDoc sur les définitions de route)
    path.resolve(process.cwd(), 'src/modules/**/*.routes.ts'),
    // Chemin vers les types/DTOs si vous définissez des schémas OpenAPI via JSDoc (@openapi)
    path.resolve(process.cwd(), 'src/modules/**/*.types.ts'),
    path.resolve(process.cwd(), 'src/common/types/**/*.ts'),
    // Il est moins courant de scanner les fichiers d'erreurs, préférez définir ErrorResponse dans components.schemas
    // path.resolve(process.cwd(), 'src/common/errors/*.ts'),
  ],
};

let swaggerSpec: SwaggerDefinition | null = null;

try {
  // Générer la spécification Swagger
  const generatedSpec = swaggerJsdoc(options) as SwaggerDefinition;

  // Vérifications de base
  if (!generatedSpec) {
    throw new Error('Swagger specification generation resulted in undefined object.');
  }
  if (!generatedSpec.paths || Object.keys(generatedSpec.paths).length === 0) {
    logger.warn(
      'Swagger spec generated, but no paths were found. Check JSDoc annotations and `apis` paths in swagger.ts.',
    );
  } else {
    const pathCount = Object.keys(generatedSpec.paths).length;
    logger.info(`Swagger specification generated successfully with ${pathCount} path(s).`);
  }

  // logger.debug(generatedSpec, 'Generated Swagger Spec:'); // Décommentez pour voir le spec complet en mode debug

  // Optionnel: Validation plus poussée du schéma généré
  // import swaggerValidator from 'swagger-spec-validator';
  // swaggerValidator.validate(generatedSpec as any, (err, result) => {
  //    if (err) { logger.error(err, "Swagger validation error (schema level)"); }
  //    if (result && !result.valid) { logger.warn({ warnings: result.warnings, errors: result.errors }, "Swagger validation issues found"); }
  // });

  swaggerSpec = generatedSpec;
} catch (error: any) {
  logger.error(error, 'Failed to generate Swagger specification');
  // Créer un objet spec de secours en cas d'erreur
  swaggerSpec = {
    openapi: '3.0.0',
    info: { title: 'API Docs (Error Generating Spec)', version: apiVersion },
    paths: {},
    servers: options.definition?.servers ?? [], // Garder les serveurs définis
  };
}

// Exporter la spécification (ou la version de secours)
// Utiliser module.exports pour une meilleure compatibilité lors de l'import initial dans app.ts
export default swaggerSpec;
