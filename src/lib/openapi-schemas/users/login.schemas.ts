export const authSchemas = {
  LoginInput: {
    type: 'object',
    required: ['email', 'password'],
    properties: {
      email: { type: 'string', format: 'email' },
      password: { type: 'string' },
    },
  },

  LoginResponse: {
    type: 'object',
    properties: {
      token: { type: 'string' },
      user: { $ref: '#/components/schemas/User' },
    },
  },

  LogoutResponse: {
    type: 'object',
    properties: {
      message: { type: 'string' },
    },
  },

  PasswordResetRequestInput: {
    type: 'object',
    required: ['email'],
    properties: {
      email: { type: 'string', format: 'email' },
      language: { type: 'string', enum: ['fr', 'en'], default: 'en' },
    },
  },

  PasswordResetInput: {
    type: 'object',
    required: ['code', 'newPassword'],
    properties: {
      code: { type: 'string' },
      newPassword: { type: 'string', minLength: 8 },
    },
  },

  PasswordConfirmInput: {
    type: 'object',
    required: ['code'],
    properties: {
      code: { type: 'string' },
    },
  },

  ExpiredPasswordUpdateInput: {
    type: 'object',
    required: ['email', 'newPassword'],
    properties: {
      email: { type: 'string', format: 'email' },
      newPassword: { type: 'string', minLength: 8 },
    },
  },

  PasswordOperationResponse: {
    type: 'object',
    properties: {
      success: { type: 'boolean' },
      message: { type: 'string' },
    },
  },

  TokenRefreshResponse: {
    type: 'object',
    properties: {
      token: { type: 'string' },
    },
  },

  ExpiredPasswordUpdateResponse: {
    type: 'object',
    properties: {
      token: { type: 'string' },
    },
  },
};
