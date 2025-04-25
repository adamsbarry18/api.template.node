import { resolve } from 'path';
import { pathToFileURL } from 'url';

import { Router } from 'express';
import { glob } from 'glob'; // Use async import

import { registerRoutes } from '../common/routing/register';
import logger from '../lib/logger';

/**
 * Dynamically discovers and registers all routes defined in `*.routes.{ts,js}` files
 * within the `src/modules` directory.
 *
 * @returns {Promise<Router>} A promise that resolves with the Express router
 *                            containing all registered routes.
 * @throws {Error} If file searching or route registration fails.
 */
async function initializeApiRouter(): Promise<Router> {
  const apiRouter = Router();
  const modulesPath = resolve(process.cwd(), 'src/modules');
  // Ensure cross-OS path compatibility
  const globPattern = resolve(modulesPath, '**/*.routes.{ts,js}').replace(/\\/g, '/');

  logger.info(`Searching for route files using pattern: ${globPattern}`);

  let routeFiles: string[];
  try {
    // Use async glob
    routeFiles = await glob(globPattern, { absolute: true });
  } catch (error) {
    logger.error(
      { err: error },
      `Failed to execute glob pattern for route discovery: ${globPattern}`,
    );
    // Propagate the error as route discovery is critical
    throw new Error(
      `Route discovery failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (routeFiles.length === 0) {
    logger.warn(`No route files found matching pattern: ${globPattern}. API might have no routes.`);
    // Return the empty router if no files are found
    return apiRouter;
  }

  logger.info(`Found ${routeFiles.length} route file(s). Registering routes...`);

  const registrationPromises = routeFiles.map(async (routeFile) => {
    const relativePath = routeFile.replace(process.cwd(), '.');
    try {
      const fileURL = pathToFileURL(routeFile).toString();

      // Dynamically import the module
      const importedModule = await import(fileURL);

      // Prefer default export, otherwise take the first named export
      const controllerClass =
        importedModule.default || importedModule[Object.keys(importedModule)[0]];

      if (typeof controllerClass === 'function' && controllerClass.prototype) {
        const controllerName = controllerClass.name || '[Anonymous Controller]';
        logger.info(`  Registering routes from ${relativePath} using controller ${controllerName}`);
        registerRoutes(apiRouter, controllerClass);
      } else {
        logger.warn(
          `  Skipping file ${relativePath}: No valid controller class found as default export or first named export. Found type: ${typeof controllerClass}`,
        );
      }
    } catch (error) {
      logger.error(
        { err: error },
        `  Failed to load or register routes from file: ${relativePath}`,
      );
      // Propagate the error to fail Promise.all
      throw new Error(
        `Failed to process route file ${relativePath}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  });

  try {
    // Wait for all imports and registrations to complete
    await Promise.all(registrationPromises);
    logger.info('✅ All dynamic routes registered successfully.');
  } catch (error) {
    logger.error({ err: error }, '❌ Failed to register all dynamic routes.');
    // Propagate the global error if any registration failed
    throw error;
  }

  return apiRouter;
}

// Export the promise that will resolve with the router once it's ready.
// Consumers (app.ts, tests) MUST await this promise.
export const initializedApiRouter: Promise<Router> = initializeApiRouter();
