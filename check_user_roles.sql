-- Check if user 'customer' exists and has roles
SELECT u.id, u.username, u.email, r.name as role_name 
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.username = 'customer';

-- Check all users and their roles
SELECT u.username, u.email, GROUP_CONCAT(r.name) as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id  
LEFT JOIN roles r ON ur.role_id = r.id
GROUP BY u.id, u.username, u.email;
