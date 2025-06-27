# API Template Node.js

A modern, modular, and scalable RESTful API template for quickly initializing Node.js projects with robust architecture and built-in best practices.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-0.0.1-green.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.8.3-blue.svg)

---

## 🚀 Introduction

### What is this template?

This RESTful API template is designed to **accelerate development** of your Node.js projects by providing a **modular and scalable architecture** ready to use with:

- ✅ **Complete Authentication** : JWT + OAuth providers (Google)
- ✅ **Modular Architecture** : Domain-Driven Design (DDD)
- ✅ **User Management** : Complete CRUD with roles and permissions
- ✅ **Robust Validation** : Zod for data validation
- ✅ **Automated Testing** : Complete test suite with Docker
- ✅ **API Documentation** : Auto-generated Swagger/OpenAPI
- ✅ **Internationalization** : Multi-language support (EN/FR)
- ✅ **Enhanced Security** : Security headers, validation, audit

### Why use this template?

- **Save time** : Ready architecture, no need to configure everything
- **Best practices** : Structured and maintainable code
- **Scalable** : Easy to add new modules
- **Production-ready** : Tests, CI/CD, Docker, monitoring
- **Documented** : Commented code and complete documentation

---

## 🏗️ Architecture

### Modular Structure

```
src/
├── api/                    # API entry point and dynamic route registration
├── app.ts                  # Express configuration
├── common/                 # Shared errors, middleware, models, routing, types, utils
├── config/                 # App and HTTP configuration
├── database/               # Data source and migrations
├── lib/                    # Logger, mailer, openapi schemas, redis
├── locales/                # Email templates (en, fr)
├── modules/                # Business modules (auth, users, etc.)
│   ├── auth/              # JWT + OAuth authentication
│   ├── users/             # User management
│   └── [other-modules]/   # New modules to add
└── tests/                  # Test utilities and docker-compose
```

### Architecture Principles

- **Domain-Driven Design (DDD)** : Clear separation of responsibilities
- **Modularity** : Each module is independent and reusable
- **Scalability** : Easy to add new modules
- **Testability** : Unit and integration tests
- **Security** : Validation, authentication, authorization

---

## 🛠️ Features

### 🔐 Authentication & Authorization
- **JWT Authentication** : Secure tokens with expiration
- **OAuth 2.0 Providers** : Integrated Google OAuth
- **Role Management** : Flexible permission system
- **Enhanced Security** : Security headers, input validation

### 👥 User Management
- **Complete CRUD** : Create, read, update, delete
- **User Profiles** : Preferences, metadata
- **Password Management** : Reset, expiration, complexity
- **User Status** : Active, inactive, expired

### 🧪 Testing & Quality
- **Unit Tests** : Vitest + Supertest
- **Integration Tests** : Test database with Docker
- **CI/CD** : Automated GitHub Actions pipeline
- **Linting & Formatting** : ESLint + Prettier

### 📚 Documentation
- **API Documentation** : Auto-generated Swagger/OpenAPI
- **Documented Code** : JSDoc and comments
- **Complete README** : Installation and usage guide

---

## 🚀 Quick Start

### Prerequisites

```bash
node >= 20.0.0
npm >= 10.0.0
docker >= 20.0.0
docker-compose >= 2.0.0
```

### Installation

1. **Clone the template**
   ```bash
   git clone https://github.com/adamsbarry18/api.template.node.git my-api-project
   cd my-api-project
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configurations
   ```

4. **Start development services**
   ```bash
   docker compose -f src/tests/docker-compose.yml up -d
   ```

5. **Start development server**
   ```bash
   npm run dev
   ```

6. **Access API documentation**
   ```
   http://localhost:8000/api-docs
   ```

### Testing

```bash
# Complete tests with clean database
npm run test:all

# Unit tests only
npm test

# Tests with coverage
npm run test:coverage
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `NODE_ENV` | Environment (`development`, `production`, `test`) | ✅ | `development` |
| `PORT` | API port | ❌ | `8000` |
| `DB_TYPE` | Database type | ✅ | `mysql` |
| `DB_HOST` | Database host | ✅ | - |
| `DB_PORT` | Database port | ✅ | - |
| `DB_USERNAME` | Database user | ✅ | - |
| `DB_PASSWORD` | Database password | ✅ | - |
| `DB_NAME` | Database name | ✅ | - |
| `JWT_SECRET` | JWT secret key | ✅ | - |
| `REDIS_URL` | Redis connection URL | ✅ | - |

See `.env.example` for all available options.

### Adding a new module

1. **Create structure**
   ```bash
   mkdir -p src/modules/my-module/{models,services,routes,__tests__}
   ```

2. **Create entity**
   ```typescript
   // src/modules/my-module/models/my-module.entity.ts
   import { Entity, Column } from 'typeorm';
   import { Model } from '@/common/models/Model';

   @Entity({ name: 'my_module' })
   export class MyModule extends Model {
     @Column({ type: 'varchar', length: 100 })
     name!: string;
   }
   ```

3. **Add routes**
   ```typescript
   // src/modules/my-module/routes/my-module.routes.ts
   import { Router } from 'express';
   import { BaseRouter } from '@/common/routing/BaseRouter';

   export class MyModuleRoutes extends BaseRouter {
     // Implement your routes
   }
   ```

4. **Register module**
   ```typescript
   // src/modules/my-module/index.ts
   export * from './models/my-module.entity';
   export * from './routes/my-module.routes';
   ```

---

## 🐳 Deployment

### Docker

```bash
# Build image
docker build -t my-api .

# Run with environment variables
docker run --rm --env-file .env -p 8000:8000 my-api
```

### Production

```bash
# Build for production
npm run build

# Run in production
npm run prod
```

---

## 📚 API Documentation

- **Swagger UI** : `http://localhost:8000/api-docs`
- **OpenAPI JSON** : `http://localhost:8000/api-docs.json`

### Main Endpoints

#### Authentication
- `POST /api/v1/auth/login` - JWT login
- `POST /api/v1/auth/logout` - Logout
- `GET /api/v1/auth/google` - Google OAuth

#### Users
- `GET /api/v1/users` - List users
- `POST /api/v1/users` - Create user
- `GET /api/v1/users/:id` - Get user details
- `PUT /api/v1/users/:id` - Update user
- `DELETE /api/v1/users/:id` - Delete user

---

## 🧪 Testing

### Test Structure

```
src/modules/
├── auth/
│   └── __tests__/
│       ├── authorization.spec.ts
│       ├── login.spec.ts
│       └── password.services.spec.ts
└── users/
    └── __tests__/
        └── users.spec.ts
```

### Run Tests

```bash
# Complete tests with clean database
npm run test:all

# Unit tests
npm test

# Tests with coverage
npm run test:coverage

# Local tests (development)
npm run test:local
```

---

## 🔐 Security

- **JWT Authentication** : Secure tokens
- **OAuth 2.0** : Google integration
- **Input Validation** : Zod for validation
- **Security Headers** : Helmet.js
- **CORS Configured** : Cross-origin protection
- **Rate Limiting** : Attack protection
- **Audit Logging** : Action traceability

---

## 🌍 Internationalization

- **Email Templates** : EN/FR support
- **Error Messages** : Multi-language
- **Ready for Extension** : Easy to add other languages

---

## 🤝 Contributing

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## 🆘 Support

- **Issues** : [GitHub Issues](https://github.com/adamsbarry18/api.template.node/issues)

---

**⭐ Don't forget to star if this template helped you!**
