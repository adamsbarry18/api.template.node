import { authorizationSchemas } from './users/authorization.schemas';
import { authSchemas } from './users/login.schemas';
import { userSchemas } from './users/user.schemas';

export const schemas = {
  ...userSchemas,
  ...authSchemas,
  ...authorizationSchemas,
};

export const getOpenAPIComponents = (): { components: { schemas: typeof schemas } } => ({
  components: {
    schemas,
  },
});

export { userSchemas, authSchemas, authorizationSchemas };
