# 🔧 Login Issue Fix - Empty Roles in JWT Token

## 🎯 Problem Summary

**Symptom**: User can login successfully but gets `403 Forbidden` when accessing `/api/v1/users/me`

**Root Cause**: The JWT token contains `"roles":[]` (empty array) because the user in the database has no roles assigned in the `user_roles` table.

**Error in logs**:
```
Access denied: Access Denied
AuthorizationDeniedException: Access Denied
```

## 🔍 Diagnosis

Your JWT token shows:
```json
{
  "roles": [],  // <-- EMPTY! This is the problem
  "sub": "customer",
  "iat": 1762805825,
  "exp": 1762892225
}
```

The endpoint requires:
```java
@PreAuthorize("hasRole('CUSTOMER') or hasRole('EMPLOYEE') or hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
```

Since the roles array is empty, Spring Security denies access.

## ✅ Solution Options

### Option 1: Fix via SQL (Immediate Fix)

Connect to your database and run:

```bash
# Connect to MySQL/MariaDB
mysql -u root -p techtorque

# Or connect to PostgreSQL
# psql -U postgres -d techtorque
```

Then execute:
```sql
-- Check current user roles
SELECT u.username, u.email, r.name as role_name 
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.username = 'customer';

-- Assign CUSTOMER role if missing
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'customer' 
  AND r.name = 'CUSTOMER'
  AND NOT EXISTS (
    SELECT 1 FROM user_roles ur 
    WHERE ur.user_id = u.id AND ur.role_id = r.id
  );

-- Verify fix
SELECT u.username, r.name as role_name 
FROM users u
INNER JOIN user_roles ur ON u.id = ur.user_id
INNER JOIN roles r ON ur.role_id = r.id
WHERE u.username = 'customer';
```

**Quick script included**: Run `Authentication/fix_user_roles.sql`

### Option 2: Delete and Recreate Users (Clean Slate)

If you want to start fresh:

```sql
-- Delete all users (roles and other tables will be preserved)
DELETE FROM user_roles;
DELETE FROM users;

-- Restart your Authentication service to trigger DataSeeder
# The DataSeeder will recreate all default users with proper roles
```

Then restart the Authentication service:
```bash
cd Authentication/auth-service
mvn spring-boot:run
```

### Option 3: Use Admin Endpoint to Assign Role

If you have access to an admin account with a valid token:

```bash
ADMIN_TOKEN="your-admin-jwt-token"

curl -X POST "http://localhost:8081/users/customer/roles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role": "CUSTOMER",
    "action": "ASSIGN"
  }'
```

## 🧪 Verify the Fix

After applying the fix:

### 1. Login Again
```bash
curl -X POST http://localhost:8081/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer",
    "password": "cust123"
  }' | jq
```

### 2. Check JWT Token
Decode the token at https://jwt.io and verify it now shows:
```json
{
  "roles": ["CUSTOMER"],  // <-- Should have role now!
  "sub": "customer",
  ...
}
```

### 3. Test /users/me Endpoint
```bash
TOKEN="your-new-jwt-token"

curl -X GET http://localhost:8081/users/me \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected**: Should return `200 OK` with user profile

### 4. Test via API Gateway
```bash
curl -X GET http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer $TOKEN" | jq
```

## 🔧 Prevention - Ensure Data Seeder Works

Check your `application.properties` or `application.yml`:

```properties
# Make sure dev profile is active for development
spring.profiles.active=dev

# Or set environment variable
# SPRING_PROFILES_ACTIVE=dev
```

The `DataSeeder` only creates test users in `dev` profile. Make sure it's active:

```bash
# Check if seeder ran on startup
# Look for these logs when starting the service:
# "Starting data seeding..."
# "Created role: CUSTOMER"
# "Created user: customer with role CUSTOMER"
# "Data seeding completed successfully!"
```

## 📊 Database Schema Reference

Correct structure for user-role assignment:

```
users table:
+----+----------+-------------------+
| id | username | email             |
+----+----------+-------------------+
| 1  | customer | customer@...      |
+----+----------+-------------------+

roles table:
+----+----------+
| id | name     |
+----+----------+
| 1  | CUSTOMER |
+----+----------+

user_roles table (join table):
+---------+---------+
| user_id | role_id |
+---------+---------+
| 1       | 1       |  <-- This row MUST exist!
+---------+---------+
```

## 🚨 Common Causes

1. **DataSeeder didn't run** - Not in dev profile
2. **Database was reset** - Roles exist but user_roles table is empty
3. **Manual user creation** - User created without assigning roles
4. **Transaction rollback** - Role assignment failed during user creation

## 📞 Still Having Issues?

Check Authentication service logs for:
```
Hibernate: select r1_0.user_id ... from user_roles r1_0 ... where r1_0.user_id=?
```

If this query returns 0 rows, the user has no roles assigned.

Enable debug logging in `application.properties`:
```properties
logging.level.com.techtorque.auth_service=DEBUG
logging.level.org.hibernate.SQL=DEBUG
logging.level.org.springframework.security=DEBUG
```

## ✅ Summary Checklist

- [ ] User exists in database
- [ ] Roles exist in database (CUSTOMER, EMPLOYEE, ADMIN, SUPER_ADMIN)
- [ ] User-role mapping exists in `user_roles` table
- [ ] JWT token contains roles array with at least one role
- [ ] Can access `/users/me` endpoint with 200 response
- [ ] DataSeeder ran successfully on service startup

---

**Created**: 2025-11-11  
**Issue**: Empty roles in JWT causing 403 Forbidden on authenticated endpoints  
**Resolution**: Ensure user has roles assigned in user_roles table
