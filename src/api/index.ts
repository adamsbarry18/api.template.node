import { Router } from 'express';
import * as glob from 'glob';
import { resolve } from 'path';
import logger from '@/lib/logger';
import { registerRoutes } from '@/common/routing/register';

// Créer une instance de routeur Express pour agréger toutes les routes de l'API
const apiRouter = Router();
const modulesPath = resolve(process.cwd(), 'src/modules');

const globPattern = resolve(modulesPath, '**/*.routes.{ts,js}').replace(/\\/g, '/');

logger.info(`Searching for route files using pattern: ${globPattern}`);

let routeFiles: string[] = [];
try {
  routeFiles = glob.sync(globPattern, { absolute: true });
} catch (error) {
  logger.error(error, `Failed to execute glob pattern for route discovery: ${globPattern}`);
}

if (routeFiles.length === 0) {
  logger.warn(`No route files found matching pattern: ${globPattern}. API might have no routes.`);
}

routeFiles.forEach((routeFile) => {
  const relativePath = routeFile.replace(process.cwd(), '.');
  try {
    const routeModule = require(routeFile);
    const ControllerClass = routeModule.default || routeModule[Object.keys(routeModule)[0]];

    if (typeof ControllerClass === 'function' && ControllerClass.prototype) {
      logger.info(
        `Registering routes from ${relativePath} using controller ${ControllerClass.name}`,
      );
      registerRoutes(apiRouter, ControllerClass);
    } else {
      logger.warn(
        `Skipping file ${relativePath}: No valid controller class found as default export or first named export. Found type: ${typeof ControllerClass}`,
      );
    }
  } catch (error) {
    logger.error(error, `Failed to load or register routes from file: ${relativePath}`);
  }
});

export default apiRouter;
