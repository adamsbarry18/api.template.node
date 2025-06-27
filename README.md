# Innov Stocker Node

A modern, modular, and scalable inventory and business management backend for SMEs, built with Node.js, TypeScript, and Express.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-0.0.1-green.svg)

---

## 1. 🚀 Introduction

### 1.1 Project Context

### 1.2 Project Objectives

### 1.3 Project Scope

The application covers the following features:

### 1.4 Stakeholders

- **Product Owner / Sponsor:** [To be defined, e.g., Company Management]
- **End Users:** Employees in purchasing, sales, logistics, finance, store managers
- **Development Team:** Project managers, analysts, developers, testers, UX/UI designers

---

## 2. 📝 Application Overview

### 2.1 Product Philosophy

The application is designed as a complete, intuitive, and high-performance solution for business management. It aims to simplify the inherent complexity of inventory and related operations, offering a clear, aesthetic, and efficient user interface. Automation of repetitive tasks and real-time delivery of relevant information are at the heart of the product philosophy.

### 2.2 Target Audience

The application targets small and medium-sized enterprises (SMEs) across various sectors (retail, distribution, small industry, etc.) needing a robust tool to manage their goods and financial flows.

### 2.3 Technology Stack

- **Backend:** Node.js, TypeScript, Express, TypeORM, Zod, modular DDD structure (models, repositories, services, routes, tests)
- **Frontend:** Vue.js 3, SCSS, TypeScript, Pinia (state management), reusable components (not included in this repo)
- **Database:** Relational DBMS (MySQL), NoSQL (Redis)
- **API:** RESTful architecture for frontend/backend communication and future integrations
- **Authentication:** OAuth 2.0 and/or JWT (JSON Web Tokens)
- **Web Server:** Nginx
- **Hosting:** Cloud solution (e.g., AWS) for scalability and maintainability

---

## 3. 🛠 Features

- **Secure Authentication:** JWT-based authentication, OAuth 2.0 ready
- **Modular Domain-Driven Design:** Clear separation of models, repositories, services, and routes
- **Comprehensive Inventory Management:** Real-time stock, inventory sessions, alerts, and valuation
- **Purchase & Sales Automation:** End-to-end workflow from order to invoice
- **Multi-currency Support:** Manage transactions in multiple currencies
- **Data Import/Export:** Excel, CSV, and more
- **Document Generation:** Print quotes, invoices, and orders
- **Barcode/QR Code Scanning:** For fast item management
- **Cash Register & Payment Management:** Track all payment types and cash operations
- **Analytics & Reporting:** Actionable insights for better decision-making
- **Internationalization:** Ready for English and French (see `/src/locales/emails/`)

---

## 4. 🏗️ Project Structure

```bash
api.template.node/
├── src/
│   ├── api/                # API entrypoint and dynamic route registration
│   ├── app.ts              # Express app setup
│   ├── common/             # Shared errors, middleware, models, routing, types, utils
│   ├── config/             # App and HTTP configuration
│   ├── database/           # Data source and migrations
│   ├── lib/                # Logger, mailer, openapi schemas, redis
│   ├── locales/            # Email templates (en, fr)
│   ├── modules/            # Domain modules (auth, users, products, etc.)
│   └── tests/              # Test utilities and docker-compose for test DBs
├── Dockerfile
├── package.json
├── README.md
└── ...
```

---

## 5. 🚀 Getting Started

### Prerequisites

```bash
node >= 20.0.0
npm >= 10.0.0
docker >= 20.0.0
docker-compose >= 2.0.0
mysql >= 8.0
redis >= 7.0
```

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/adamsbarry18/api.template.node.git
   cd api.template.node
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Set up environment variables**

   Copy the example file and fill in your configuration:

   ```bash
   cp .env.example .env
   ```

   Edit `.env` to match your MySQL, Redis, and other settings.

4. **Run database and cache for development/testing**

   ```bash
   docker compose -f src/tests/docker-compose.yml up -d
   ```

5. **Run the development server**

   ```bash
   npm run dev
   ```

6. **Build for production**

   ```bash
   npm run build
   ```

7. **Run in production**

   ```bash
   npm run prod
   ```

---

## 6. 🐳 Docker Deployment

### Quick Start

1. **Build the Docker image**

   ```bash
   docker build -t innov-stocker-app .
   ```

2. **Run the container with environment variables**

   ```bash
   docker run --rm --env-file .env -p 8000:8000 innov-stocker-app
   ```

3. **(Optional) Use Docker Compose for local dev/test**

   ```bash
   docker compose -f src/tests/docker-compose.yml up -d
   ```

### Dockerfile

- Multi-stage build for optimized production images
- Uses `dumb-init` for proper signal handling
- Exposes port 8000

### Environment Variables

| Variable      | Description                                       | Required |
| ------------- | ------------------------------------------------- | -------- |
| `NODE_ENV`    | Environment (`development`, `production`, `test`) | Yes      |
| `PORT`        | API port (default: 8000)                          | No       |
| `DB_TYPE`     | Database type (`mysql`, ...)                      | Yes      |
| `DB_HOST`     | Database host                                     | Yes      |
| `DB_PORT`     | Database port                                     | Yes      |
| `DB_USERNAME` | Database user                                     | Yes      |
| `DB_PASSWORD` | Database password                                 | Yes      |
| `DB_NAME`     | Database name                                     | Yes      |
| `REDIS_URL`   | Redis connection string                           | Yes      |
| ...           | See `.env.example` for all options                |          |

---

## 7. 📚 API Documentation

- **Swagger/OpenAPI** available at `/api-docs` when the server is running.
- Auto-generated from code annotations and OpenAPI schemas.

---

## 8. 🧪 Testing

- **Unit & Integration Tests:**
  ```bash
  npm test
  ```
- **Test DB Services:**
  ```bash
  npm run test-db:start
  npm run test-db:stop
  ```

---

## 9. 🧑‍💻 Code Quality

- **Linting:**
  ```bash
  npm run lint
  ```
- **Formatting:**
  ```bash
  npm run format
  ```
- **Pre-commit hooks:** Husky (configured in `package.json`)

---

## 10. 🌍 Internationalization

- English and French email templates in `/src/locales/emails/`
- Ready for further i18n extension

---

## 11. 🔐 Security & Compliance

- JWT authentication
- Secure HTTP headers via Helmet
- Input validation with Zod
- Audit logging
- GDPR-compliant data handling

---

## 12. 📄 License

This project is licensed under the MIT License.

---

**For any questions, contributions, or issues, please open an issue or pull request on [GitHub](https://github.com/adamsbarry18/api.template.node).**
