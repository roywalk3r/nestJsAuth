# Auth Service (NestJS + Prisma)

A Node.js authentication service built with [NestJS](https://nestjs.com/) and [Prisma](https://www.prisma.io/), using JWT-based authentication.

## Features

- **JWT Authentication:** Secure login and token management.
- **User Management:** Create, update, and manage users.
- **Prisma ORM:** Type-safe database access.
- **Password Hashing:** Uses bcrypt for secure password storage.
- **Validation:** Uses class-validator and class-transformer for DTO validation.
- **Testing:** Jest-based unit and e2e tests.

## Project Structure

```
src/
  ├── auth/           # Authentication module (controllers, services, guards, strategies)
  ├── users/          # User management module
  ├── prisma/         # Prisma service integration
  ├── main.ts         # Application entry point
```

## Setup

```bash
pnpm install
```

## Running the Project

```bash
# Development
pnpm run start

# Watch mode
pnpm run start:dev

# Production
pnpm run build
pnpm run start:prod
```

## Testing

```bash
# Unit tests
pnpm run test

# End-to-end tests
pnpm run test:e2e
```

## Environment

Configure your `.env` file for database and JWT secrets.

## Scripts

- `start`, `start:dev`, `start:prod`: Run the application in different modes.
- `test`, `test:e2e`: Run tests.
- `lint`, `format`: Lint and format code.

## Dependencies

- `@nestjs/*`
- `@prisma/client`, `prisma`
- `bcrypt`
- `passport-jwt`
- `class-validator`, `class-transformer`
