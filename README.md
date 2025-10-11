# 🔑 Authentication & User Management Service

This service is the authoritative source for user identity, authentication, and role management within the TechTorque 2025 ecosystem.

## 🚦 Build Status

**main**

[![Build and Test Authentication Service](https://github.com/TechTorque-2025/Authentication/actions/workflows/buildtest.yaml/badge.svg)](https://github.com/TechTorque-2025/Authentication/actions/workflows/buildtest.yaml)

**dev**

[![Build and Test Authentication Service](https://github.com/TechTorque-2025/Authentication/actions/workflows/buildtest.yaml/badge.svg?branch=dev)](https://github.com/TechTorque-2025/Authentication/actions/workflows/buildtest.yaml)

**Assigned Team:** Randitha, Suweka

### 🎯 Key Responsibilities

- **User Registration & Login:** Handles new account creation and authenticates users, issuing JWT Access and Refresh Tokens.
- **Token Management:** Provides an endpoint to refresh expired Access Tokens.
- **User Profile:** Allows users to manage their own profile information.
- **RBAC:** Manages user roles (`CUSTOMER`, `EMPLOYEE`, `ADMIN`) and embeds them into the JWT.

### ⚙️ Tech Stack

- **Framework:** Java / Spring Boot
- **Database:** PostgreSQL
- **Security:** Spring Security

### ℹ️ API Information

- **Local Port:** `8081`
- **Swagger UI:** [http://localhost:8081/swagger-ui.html](http://localhost:8081/swagger-ui.html)

### 🚀 Running Locally

This service is designed to be run as part of the main `docker-compose` setup from the project's root directory.

```bash
# From the root of the TechTorque-2025 project
docker-compose up --build auth-service