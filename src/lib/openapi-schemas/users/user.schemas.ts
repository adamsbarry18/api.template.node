export const userSchemas = {
  UserInput: {
    type: 'object',
    required: ['email', 'password', 'firstname', 'level'],
    properties: {
      email: { type: 'string', format: 'email' },
      password: { type: 'string', minLength: 8 },
      firstname: { type: 'string' },
      lastname: { type: 'string', nullable: true },
      level: { type: 'integer', minimum: 0, maximum: 5 },
      internalLevel: { type: 'integer', minimum: 0 },
      internal: { type: 'boolean' },
      color: { type: 'string', nullable: true },
      passwordStatus: { type: 'string', enum: ['ACTIVE', 'VALIDATING', 'EXPIRED'] },
      preferences: { type: 'object', additionalProperties: true, nullable: true },
      permissions: {
        type: 'object',
        additionalProperties: { type: 'array', items: { type: 'string' } },
        nullable: true,
      },
      permissionsExpireAt: { type: 'string', format: 'date-time', nullable: true },
    },
  },

  UserUpdateInput: {
    type: 'object',
    properties: {
      password: { type: 'string', minLength: 8 },
      firstname: { type: 'string' },
      lastname: { type: 'string', nullable: true },
      level: { type: 'integer', minimum: 0, maximum: 5 },
      internalLevel: { type: 'integer', minimum: 0 },
      internal: { type: 'boolean' },
      color: { type: 'string', nullable: true },
      passwordStatus: { type: 'string', enum: ['ACTIVE', 'VALIDATING', 'EXPIRED'] },
      preferences: { type: 'object', additionalProperties: true, nullable: true },
      permissions: {
        type: 'object',
        additionalProperties: { type: 'array', items: { type: 'string' } },
        nullable: true,
      },
      permissionsExpireAt: { type: 'string', format: 'date-time', nullable: true },
    },
  },

  User: {
    type: 'object',
    properties: {
      id: { type: 'integer' },
      uid: { type: 'string', nullable: true },
      email: { type: 'string', format: 'email' },
      firstname: { type: 'string', nullable: true },
      lastname: { type: 'string', nullable: true },
      level: { type: 'integer' },
      internalLevel: { type: 'integer' },
      internal: { type: 'boolean' },
      color: { type: 'string', nullable: true },
      passwordStatus: { type: 'string', enum: ['ACTIVE', 'VALIDATING', 'EXPIRED'] },
      createdAt: { type: 'string', format: 'date-time', nullable: true },
      updatedAt: { type: 'string', format: 'date-time', nullable: true },
      passwordUpdatedAt: { type: 'string', format: 'date-time', nullable: true },
      preferences: { type: 'object', additionalProperties: true, nullable: true },
      permissionsExpireAt: { type: 'string', format: 'date-time', nullable: true },
    },
  },

  UserPreferencesInput: {
    type: 'object',
    additionalProperties: true,
  },

  DeleteResponse: {
    type: 'object',
    properties: {
      message: { type: 'string' },
    },
  },
};
