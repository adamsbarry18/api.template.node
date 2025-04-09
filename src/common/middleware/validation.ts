import { Request, Response, NextFunction } from '../http';
import { AnyZodObject, ZodError } from 'zod';
import { ValidationError } from '../errors/httpErrors';

// Factory pour créer un middleware de validation
export const validateRequest =
  (schema: AnyZodObject) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Valider req.body, req.query, req.params en fonction de ce que le schéma contient
      const parsed = await schema.parseAsync({
        body: req.body,
        query: req.query,
        params: req.params,
      });

      // Remplacer les objets de requête par les données validées/transformées par Zod
      req.body = parsed.body ?? req.body;
      req.query = parsed.query ?? req.query;
      req.params = parsed.params ?? req.params;

      next();
    } catch (error) {
      if (error instanceof ZodError) {
        next(new ValidationError('Validation failed', error.format()));
      } else {
        next(error);
      }
    }
  };
