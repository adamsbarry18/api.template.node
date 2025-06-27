// src/lib/openapi-schemas/authorization.schemas.ts
export const authorizationSchemas = {
  FeaturesResponse: {
    type: 'object',
    additionalProperties: {
      type: 'array',
      items: { type: 'string' },
    },
  },

  AuthorisationsByLevelResponse: {
    type: 'object',
    additionalProperties: {
      type: 'object',
      additionalProperties: {
        type: 'array',
        items: { type: 'string' },
      },
    },
  },

  AuthorisationsForLevelResponse: {
    type: 'object',
    additionalProperties: {
      type: 'array',
      items: { type: 'string' },
    },
  },

  UserAuthorisationResponse: {
    type: 'object',
    properties: {
      authorisation: {
        type: 'object',
        additionalProperties: {
          type: 'array',
          items: { type: 'string' },
        },
      },
      expire: {
        type: 'string',
        format: 'date-time',
        nullable: true,
      },
      level: {
        type: 'integer',
      },
    },
  },

  TemporaryAuthorizationInput: {
    type: 'object',
    properties: {
      expire: {
        type: 'string',
        format: 'date-time',
        nullable: true,
      },
      level: {
        type: 'integer',
        minimum: 0,
        maximum: 5,
      },
    },
  },

  AuthorizationUpdateInput: {
    type: 'object',
    properties: {
      level: {
        type: 'integer',
        minimum: 0,
        maximum: 5,
      },
      authorisationOverrides: {
        type: 'string',
        nullable: true,
      },
    },
  },

  AuthorizationOperationResponse: {
    type: 'object',
    properties: {
      success: { type: 'boolean', default: true },
    },
  },
};
