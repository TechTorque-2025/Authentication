# 🔑 Authentication & User Management Service

This service is the authoritative source for user identity, authentication, and role management within the TechTorque 2025 ecosystem.

## 🚦 Build Status

**main**

[![Build and Test Authentication Service](https://github.com/TechTorque-2025/Authentication/actions/workflows/buildtest.yaml/badge.svg)](https://github.com/TechTorque-2025/Authentication/actions/workflows/buildtest.yaml)

**dev**

[![Build and Test Authentication Service](https://github.com/TechTorque-2025/Authentication/actions/workflows/buildtest.yaml/badge.svg?branch=dev)](https://github.com/TechTorque-2025/Authentication/actions/workflows/buildtest.yaml)

**Assigned Team:** Randitha, Suweka

## ✅ Implementation Status

**COMPLETE** - 25/25 endpoints (100%)

- ✅ Core Authentication (9/9) - Email verification, login, refresh tokens, password reset
- ✅ User Profile Management (5/5) - Profile updates, preferences
- ✅ Admin User Management (11/11) - User CRUD, role management

See [COMPLETE_IMPLEMENTATION_REPORT.md](COMPLETE_IMPLEMENTATION_REPORT.md) for full details.

### 🎯 Key Responsibilities

- **User Registration & Login:** Email verification required, JWT + refresh token issued
- **Token Management:** JWT refresh tokens with 7-day expiry
- **User Profile:** Full profile and preferences management
- **Password Reset:** Token-based password reset via email
- **RBAC:** Manages user roles (CUSTOMER, EMPLOYEE, ADMIN, SUPER_ADMIN)

### ⚙️ Tech Stack

- **Framework:** Java / Spring Boot 3.5.6
- **Database:** PostgreSQL
- **Security:** Spring Security + JWT
- **Email:** Spring Mail (optional, disabled by default)

### ℹ️ API Information

- **Local Port:** `8081`
- **Swagger UI:** [http://localhost:8081/swagger-ui.html](http://localhost:8081/swagger-ui.html)

### 🚀 Running Locally

This service is designed to be run as part of the main `docker-compose` setup from the project's root directory.

```bash
```bash
# From the root of the TechTorque-2025 project
docker-compose up --build auth-service
```

### 🧪 Testing

Run the comprehensive test script:

```bash
cd Authentication
./test-auth-complete.sh
```

### 📚 Documentation

- [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) - Feature overview and usage guide
- [COMPLETE_IMPLEMENTATION_REPORT.md](COMPLETE_IMPLEMENTATION_REPORT.md) - Detailed technical report
- [Swagger UI](http://localhost:8081/swagger-ui.html) - Interactive API documentation

### 🆕 New Features (v2.0.0)

- Email verification system
- JWT refresh tokens  
- Password reset flow
- Profile management
- User preferences
- Enhanced security

**Status:** Production Ready (pending email SMTP configuration)