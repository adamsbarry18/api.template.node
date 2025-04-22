import { AuthSchemas } from './users/login.schemas';
import { AuthorizationSchemas } from './users/authorization.schemas';
import { UserSchemas } from './users/user.schemas';

export const schemas = {
  ...UserSchemas,
  ...AuthSchemas,
  ...AuthorizationSchemas,
};

export const getOpenAPIComponents = () => ({
  components: {
    schemas,
  },
});
