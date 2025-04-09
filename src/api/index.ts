import { registerRoutes } from '@/common/routing/register';
import { Router } from 'express';
import * as glob from 'glob';
import { resolve } from 'path';
import logger from '@/lib/logger';

const apiRouter = Router();
const modulesPath = resolve(process.cwd(), 'src/modules');
const globPattern = resolve(modulesPath, '**/*.routes.{ts,js}').replace(/\\/g, '/');

let routeFiles: string[] = [];
try {
  routeFiles = glob.sync(globPattern, { absolute: true });
} catch (error) {
  logger.error(error, `Failed to execute glob pattern: ${globPattern}`);
}
routeFiles.forEach((routeFile) => {
  const relativePath = routeFile.replace(process.cwd(), '.');
  try {
    const routeModule = require(routeFile);
    const ControllerClass = routeModule.default || routeModule[Object.keys(routeModule)[0]];

    if (typeof ControllerClass === 'function' && ControllerClass.prototype) {
      logger.info(`Registering routes from ${relativePath}`);
      registerRoutes(apiRouter, ControllerClass);
    } else {
      logger.warn(
        `Skipping file ${relativePath}: No valid controller class found as default export. Found type: ${typeof ControllerClass}`,
      );
    }
  } catch (error) {
    logger.error(error, `Failed to load or register routes from file: ${relativePath}`);
  }
});

export default apiRouter;
