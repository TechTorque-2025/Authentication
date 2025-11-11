-- Fix: Assign CUSTOMER role to user 'customer' if missing
-- Run this SQL script in your database

-- First, verify the issue
SELECT 'Checking user roles...' as status;
SELECT u.username, u.email, r.name as role_name 
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.username = 'customer';

-- Insert CUSTOMER role for user 'customer' if not exists
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'customer' 
  AND r.name = 'CUSTOMER'
  AND NOT EXISTS (
    SELECT 1 FROM user_roles ur 
    WHERE ur.user_id = u.id AND ur.role_id = r.id
  );

-- Verify the fix
SELECT 'After fix:' as status;
SELECT u.username, u.email, r.name as role_name 
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.username = 'customer';
