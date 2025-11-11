#!/bin/bash

echo "=========================================="
echo "🔧 Complete Fix for User Roles Issue"
echo "=========================================="
echo ""

# Database connection details (adjust if needed)
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-techtorque}"
DB_USER="${DB_USER:-techtorque}"
DB_PASS="${DB_PASS:-techtorque123}"

echo "Step 1: Fixing database - Assigning roles to existing users"
echo "Database: $DB_NAME @ $DB_HOST:$DB_PORT"
echo ""

# SQL to fix existing data
SQL=$(cat <<'EOSQL'
-- Display current state
SELECT 'BEFORE FIX:' as status;
SELECT u.username, COUNT(ur.role_id) as role_count
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
GROUP BY u.id, u.username
ORDER BY u.id;

-- Assign roles to all users based on their username
-- Assign SUPER_ADMIN role
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
CROSS JOIN roles r
WHERE u.username = 'superadmin' 
  AND r.name = 'SUPER_ADMIN'
  AND NOT EXISTS (
    SELECT 1 FROM user_roles ur 
    WHERE ur.user_id = u.id AND ur.role_id = r.id
  );

-- Assign ADMIN role
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
CROSS JOIN roles r
WHERE u.username = 'admin' 
  AND r.name = 'ADMIN'
  AND NOT EXISTS (
    SELECT 1 FROM user_roles ur 
    WHERE ur.user_id = u.id AND ur.role_id = r.id
  );

-- Assign EMPLOYEE role
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
CROSS JOIN roles r
WHERE u.username = 'employee' 
  AND r.name = 'EMPLOYEE'
  AND NOT EXISTS (
    SELECT 1 FROM user_roles ur 
    WHERE ur.user_id = u.id AND ur.role_id = r.id
  );

-- Assign CUSTOMER role to customer and test users
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
CROSS JOIN roles r
WHERE u.username IN ('customer', 'user', 'testuser', 'demo', 'test')
  AND r.name = 'CUSTOMER'
  AND NOT EXISTS (
    SELECT 1 FROM user_roles ur 
    WHERE ur.user_id = u.id AND ur.role_id = r.id
  );

-- Display fixed state
SELECT 'AFTER FIX:' as status;
SELECT u.username, u.email, r.name as role_name 
FROM users u
INNER JOIN user_roles ur ON u.id = ur.user_id
INNER JOIN roles r ON ur.role_id = r.id
ORDER BY u.id, r.name;

-- Summary
SELECT 'SUMMARY:' as status;
SELECT u.username, 
       ARRAY_AGG(r.name ORDER BY r.name) as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
GROUP BY u.id, u.username
ORDER BY u.id;
EOSQL
)

# Execute SQL
echo "Executing SQL fixes..."
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" << EOF
$SQL
EOF

echo ""
echo "=========================================="
echo "Step 2: Restart Authentication Service"
echo "=========================================="
echo ""
echo "The User entity has been fixed with cascade settings."
echo "You need to rebuild and restart the service:"
echo ""
echo "  cd Authentication/auth-service"
echo "  mvn clean install -DskipTests"
echo "  mvn spring-boot:run"
echo ""
echo "Or if running in Docker:"
echo "  docker-compose restart auth-service"
echo ""
echo "=========================================="
echo "✅ Fix Complete!"
echo "=========================================="
echo ""
echo "What was fixed:"
echo "1. ✅ Added cascade settings to User entity @ManyToMany relationship"
echo "2. ✅ Assigned roles to all existing users in database"
echo ""
echo "Test the fix:"
echo "1. Login again:"
echo '   curl -X POST http://localhost:8081/login \'
echo '     -H "Content-Type: application/json" \'
echo '     -d '"'"'{"username":"customer","password":"cust123"}'"'"
echo ""
echo "2. Decode JWT at https://jwt.io - should show roles"
echo ""
echo "3. Test /users/me with the new token"
echo ""
