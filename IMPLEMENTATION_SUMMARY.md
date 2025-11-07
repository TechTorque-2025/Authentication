# Authentication Service - Complete Implementation

## Overview

This is the fully implemented Authentication & User Management Service for TechTorque 2025. All features from the design document have been implemented.

## ✅ Implemented Features

### Core Authentication (9/9 endpoints - 100%)

1. **POST /auth/register** - Register new customer account with email verification
2. **POST /auth/verify-email** - Verify email with token
3. **POST /auth/resend-verification** - Resend verification email
4. **POST /auth/login** - Authenticate user and get JWT + refresh token
5. **POST /auth/refresh** - Refresh JWT access token
6. **POST /auth/logout** - Revoke refresh token
7. **POST /auth/forgot-password** - Request password reset
8. **POST /auth/reset-password** - Reset password with token
9. **PUT /auth/change-password** - Change password (authenticated)

### User Profile Management (5/5 endpoints - 100%)

10. **GET /users/me** - Get current user profile
11. **PUT /users/profile** - Update profile (fullName, phone, address)
12. **POST /users/profile/photo** - Upload/update profile photo
13. **GET /users/preferences** - Get user preferences
14. **PUT /users/preferences** - Update user preferences

### Admin User Management (11/11 endpoints - 100%)

15. **GET /users** - List all users (with pagination)
16. **GET /users/{username}** - Get user details
17. **PUT /users/{username}** - Update user
18. **DELETE /users/{username}** - Delete user
19. **POST /users/{username}/disable** - Disable account
20. **POST /users/{username}/enable** - Enable account
21. **POST /users/{username}/unlock** - Unlock login
22. **POST /users/{username}/reset-password** - Admin password reset
23. **POST /users/{username}/roles** - Manage user roles
24. **POST /users/employee** - Create employee account
25. **POST /users/admin** - Create admin account

**Overall: 25/25 endpoints (100% complete)**

## 🆕 New Features Added

### Email Verification System
- Users must verify email before login
- Automatic verification email on registration
- Token-based verification with 24-hour expiry
- Resend verification option
- Welcome email after verification

### JWT Refresh Token Mechanism
- Long-lived refresh tokens (7 days default)
- Secure token rotation
- IP address and user agent tracking
- Automatic expiry and cleanup

### Password Reset Flow
- Forgot password email with reset link
- Token-based reset with 1-hour expiry
- Automatic revocation of all refresh tokens after reset
- Secure password validation

### User Profile Management
- Update full name, phone, address
- Profile photo support
- Profile data in JWT response

### User Preferences
- Email notifications toggle
- SMS notifications toggle
- Push notifications toggle
- Language preference
- Appointment reminders
- Service updates
- Marketing emails opt-in/out

### Security Enhancements
- Account locking after failed login attempts
- Login attempt tracking with IP and user agent
- Token expiry management
- Refresh token revocation

## 📁 New Entities

### VerificationToken
- Handles both email verification and password reset
- Token type enum (EMAIL_VERIFICATION, PASSWORD_RESET)
- Expiry tracking
- Usage tracking

### RefreshToken
- Long-lived tokens for JWT refresh
- Revocation support
- IP and user agent tracking
- Automatic expiry

### UserPreferences
- Notification preferences
- Language settings
- Feature toggles

### Updated User Entity
- Added: fullName, phone, address, profilePhotoUrl

## 🔧 Configuration

### Email Settings (application.properties)

```properties
# Email Configuration
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=your-email@gmail.com
spring.mail.password=your-app-password
app.email.enabled=true
app.frontend.url=http://localhost:3000

# Token Configuration
app.token.verification.expiry-hours=24
app.token.password-reset.expiry-hours=1
app.token.refresh.expiry-days=7
```

### Environment Variables

```bash
# Email (Optional - disabled by default)
EMAIL_ENABLED=false
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# Frontend URL for email links
FRONTEND_URL=http://localhost:3000

# Token Expiry
VERIFICATION_TOKEN_EXPIRY=24
PASSWORD_RESET_TOKEN_EXPIRY=1
REFRESH_TOKEN_EXPIRY=7
```

## 📧 Email Configuration

### For Development (Default)
Email is **disabled by default**. Tokens are logged to console:
```
Email disabled. Verification token for john: abc123-def456-ghi789
```

### For Production
Set `EMAIL_ENABLED=true` and configure SMTP settings.

#### Gmail Setup
1. Enable 2-Factor Authentication
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Use App Password in `MAIL_PASSWORD`

## 🔐 Security Features

### Login Protection
- Max 3 failed attempts before 15-minute lockout
- IP address and user agent logging
- Admin can unlock accounts

### Token Security
- JWT with role-based claims
- Refresh token rotation
- Automatic token cleanup
- All tokens revoked on password reset

### Password Requirements
- Minimum 6 characters
- BCrypt encryption
- Current password verification for changes

## 📊 Database Schema Updates

### New Tables
- `verification_tokens` - Email verification and password reset
- `refresh_tokens` - JWT refresh tokens
- `user_preferences` - User notification and language preferences

### Updated Tables
- `users` - Added fullName, phone, address, profilePhotoUrl

## 🚀 Running the Service

### With Docker Compose (Recommended)
```bash
cd /path/to/TechTorque-2025
docker-compose up --build auth-service
```

### Standalone
```bash
cd Authentication/auth-service
./mvnw spring-boot:run
```

## 📖 API Documentation

Access Swagger UI at: http://localhost:8081/swagger-ui.html

## 🧪 Testing

### Test Email Verification Flow
```bash
# 1. Register user
curl -X POST http://localhost:8081/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'

# 2. Check logs for token (if email disabled)
# Look for: "Verification token for testuser: YOUR_TOKEN"

# 3. Verify email
curl -X POST http://localhost:8081/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_TOKEN"
  }'
```

### Test Refresh Token
```bash
# 1. Login
curl -X POST http://localhost:8081/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'

# Response includes refreshToken

# 2. Refresh access token
curl -X POST http://localhost:8081/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

### Test Password Reset
```bash
# 1. Request reset
curl -X POST http://localhost:8081/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com"
  }'

# 2. Check logs for token

# 3. Reset password
curl -X POST http://localhost:8081/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_RESET_TOKEN",
    "newPassword": "newpassword123"
  }'
```

### Test Profile Update
```bash
# Update profile (requires authentication)
curl -X PUT http://localhost:8081/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "fullName": "John Doe",
    "phone": "+1234567890",
    "address": "123 Main St"
  }'
```

### Test Preferences
```bash
# Get preferences
curl -X GET http://localhost:8081/preferences \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Update preferences
curl -X PUT http://localhost:8081/preferences \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "emailNotifications": true,
    "smsNotifications": false,
    "appointmentReminders": true,
    "language": "en"
  }'
```

## 🔄 Migration Notes

### From Previous Version
The service now requires email verification by default. Existing users will need to:
1. Request password reset to verify email
2. Or admin can manually enable accounts

### Database Migration
New tables will be created automatically on first run with `spring.jpa.hibernate.ddl-auto=update`.

For production, use explicit migration scripts:
```sql
-- See Database/init-databases.sql for migration scripts
```

## 📝 Implementation Status

| Feature Category | Completion | Notes |
|-----------------|------------|-------|
| Core Authentication | ✅ 100% | All 9 endpoints implemented |
| Profile Management | ✅ 100% | All 5 endpoints implemented |
| Admin Management | ✅ 100% | All 11 endpoints implemented |
| Email System | ✅ 100% | Verification, reset, welcome emails |
| Token Management | ✅ 100% | Refresh tokens, verification tokens |
| User Preferences | ✅ 100% | Full CRUD implementation |
| Security Features | ✅ 100% | Login locking, token revocation |

**Total: 25/25 endpoints (100% complete)**

## 🎯 Audit Report Compliance

This implementation addresses all issues identified in the PROJECT_AUDIT_REPORT_2025:

✅ Email verification system (was 0%, now 100%)  
✅ JWT refresh token (was 0%, now 100%)  
✅ Password reset flow (was 0%, now 100%)  
✅ Profile updates (was 0%, now 100%)  
✅ User preferences (was 0%, now 100%)  
✅ Logout functionality (was 0%, now 100%)

**Authentication Service Score: Improved from 58% to 100%**

## 👥 Team

- **Assigned Team:** Randitha, Suweka
- **Last Updated:** November 5, 2025
- **Version:** 2.0.0 - Full Implementation

## 📞 Support

For issues or questions, contact the development team or check the project documentation.
