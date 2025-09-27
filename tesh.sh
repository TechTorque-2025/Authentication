#!/bin/bash

# ==============================================================================
# Comprehensive Test Script for the TechTorque Authentication Service
# ==============================================================================
#
# This script validates the entire functionality of the auth-service, including:
# - Public endpoints (health, register, login)
# - User self-service (get profile, change password)
# - Admin capabilities (create employee, list users, manage accounts)
# - Super-Admin security rules (create admin, role management)
# - Negative tests for security permissions.
#
# Prerequisites:
#   - The auth-service must be running on localhost:8081.
#   - `curl` must be installed.
#   - `jq` must be installed for parsing JSON (e.g., `sudo apt-get install jq`).
#
# ==============================================================================

# --- Configuration ---
BASE_URL="http://localhost:8081/api/v1"
PASS_COUNT=0
FAIL_COUNT=0

# --- Helper Functions for Colored Output ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print test status
print_status() {
    local message=$1
    local status=$2
    if [ "$status" == "PASS" ]; then
        echo -e "${GREEN}[PASS]${NC} $message"
        ((PASS_COUNT++))
    else
        echo -e "${RED}[FAIL]${NC} $message"
        ((FAIL_COUNT++))
    fi
}

# --- Core Test Runner Function ---
# Usage: run_test "Test Name" <Expected HTTP Status> <Method> <Endpoint> [JWT Token] [JSON Data]
run_test() {
    local test_name=$1
    local expected_status=$2
    local method=$3
    local endpoint=$4
    local token=$5
    local data=$6

    local headers=(-H "Content-Type: application/json")
    if [ -n "$token" ]; then
        headers+=(-H "Authorization: Bearer $token")
    fi

    # The -w "%{http_code}" flag makes curl output only the HTTP status code.
    # The -s flag makes it silent, and -o /dev/null discards the body.
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
        "${headers[@]}" \
        -d "$data" \
        "$BASE_URL$endpoint")

    if [ "$http_code" == "$expected_status" ]; then
        print_status "$test_name (Expected $expected_status, Got $http_code)" "PASS"
    else
        print_status "$test_name (Expected $expected_status, Got $http_code)" "FAIL"
    fi
}

# --- Main Test Execution ---

echo -e "${YELLOW}===============================================${NC}"
echo -e "${YELLOW}  Starting Auth Service Integration Tests...  ${NC}"
echo -e "${YELLOW}===============================================${NC}"

# Check for jq dependency
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: 'jq' is not installed. Please install it to run these tests.${NC}"
    exit 1
fi

# === 1. Public Endpoints ===
echo -e "\n--- Testing Public Endpoints ---"
run_test "Health check" 200 "GET" "/auth/health"

# Generate a unique username for this test run
UNIQUE_ID=$RANDOM
CUSTOMER_USER="testcust$UNIQUE_ID"
CUSTOMER_EMAIL="testcust$UNIQUE_ID@techtorque.com"
run_test "Register a new customer" 200 "POST" "/auth/register" "" \
  '{"username":"'$CUSTOMER_USER'","email":"'$CUSTOMER_EMAIL'","password":"password123"}'

# === 2. Login and Token Extraction ===
echo -e "\n--- Logging in and Acquiring JWTs ---"

# Log in as SUPER_ADMIN to get a token
SUPER_ADMIN_TOKEN=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"superadmin","password":"superadmin123"}' "$BASE_URL/auth/login" | jq -r '.token')
if [ "$SUPER_ADMIN_TOKEN" != "null" ]; then print_status "Logged in as SUPER_ADMIN" "PASS"; else print_status "Failed to log in as SUPER_ADMIN" "FAIL"; fi

# Log in as ADMIN to get a token
ADMIN_TOKEN=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}' "$BASE_URL/auth/login" | jq -r '.token')
if [ "$ADMIN_TOKEN" != "null" ]; then print_status "Logged in as ADMIN" "PASS"; else print_status "Failed to log in as ADMIN" "FAIL"; fi

# Log in as the new CUSTOMER to get a token
CUSTOMER_TOKEN=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"'$CUSTOMER_USER'","password":"password123"}' "$BASE_URL/auth/login" | jq -r '.token')
if [ "$CUSTOMER_TOKEN" != "null" ]; then print_status "Logged in as new CUSTOMER" "PASS"; else print_status "Failed to log in as new CUSTOMER" "FAIL"; fi

# === 3. User Self-Service Endpoints ===
echo -e "\n--- Testing User Self-Service ---"
run_test "Customer can get their own profile (/me)" 200 "GET" "/users/me" "$CUSTOMER_TOKEN"
run_test "Customer can change their own password" 200 "POST" "/users/me/change-password" "$CUSTOMER_TOKEN" \
  '{"currentPassword":"password123", "newPassword":"newPassword456"}'

# === 4. Admin-Level Endpoints ===
echo -e "\n--- Testing Admin Capabilities ---"
NEW_EMP_USER="testemp$UNIQUE_ID"
run_test "Admin can create an Employee" 201 "POST" "/auth/users/employee" "$ADMIN_TOKEN" \
  '{"username":"'$NEW_EMP_USER'","email":"'$NEW_EMP_USER'@techtorque.com","password":"password123"}'
run_test "Admin can list all users" 200 "GET" "/users" "$ADMIN_TOKEN"
run_test "Admin can disable a user" 200 "POST" "/users/$CUSTOMER_USER/disable" "$ADMIN_TOKEN"
run_test "Admin can re-enable a user" 200 "POST" "/users/$CUSTOMER_USER/enable" "$ADMIN_TOKEN"

# === 5. Super-Admin-Level Endpoints and Security Rules ===
echo -e "\n--- Testing Super-Admin Capabilities & Security Rules ---"
NEW_ADMIN_USER="newadmin$UNIQUE_ID"
run_test "Super-Admin can create an Admin" 201 "POST" "/auth/users/admin" "$SUPER_ADMIN_TOKEN" \
  '{"username":"'$NEW_ADMIN_USER'","email":"'$NEW_ADMIN_USER'@techtorque.com","password":"password123"}'
run_test "Super-Admin can assign ADMIN role to an employee" 200 "POST" "/users/$NEW_EMP_USER/roles" "$SUPER_ADMIN_TOKEN" \
  '{"roleName":"ADMIN", "action":"ASSIGN"}'

# === 6. Negative Security Tests (Crucial!) ===
echo -e "\n--- Testing Security Denials (Negative Tests) ---"
run_test "FAIL: Regular Admin CANNOT create another Admin" 403 "POST" "/auth/users/admin" "$ADMIN_TOKEN" \
  '{"username":"fakeadmin","email":"fake@admin.com","password":"password123"}'
run_test "FAIL: Regular Admin CANNOT assign ADMIN role" 403 "POST" "/users/$CUSTOMER_USER/roles" "$ADMIN_TOKEN" \
  '{"roleName":"ADMIN", "action":"ASSIGN"}'
run_test "FAIL: Customer CANNOT list all users" 403 "GET" "/users" "$CUSTOMER_TOKEN"
run_test "FAIL: Customer CANNOT create an Employee" 403 "POST" "/auth/users/employee" "$CUSTOMER_TOKEN" \
  '{"username":"fakeemployee","email":"fake@employee.com","password":"password123"}'

# === 7. Final Cleanup Test ===
echo -e "\n--- Testing Final Cleanup Action ---"
run_test "Admin can delete a user" 200 "DELETE" "/users/$CUSTOMER_USER" "$ADMIN_TOKEN"


# === Summary ===
echo -e "\n${YELLOW}===============================================${NC}"
echo -e "${YELLOW}                  Test Summary                 ${NC}"
echo -e "${YELLOW}===============================================${NC}"
echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
echo -e "${RED}Failed: $FAIL_COUNT${NC}"
echo -e "${YELLOW}===============================================${NC}"

# Return exit code based on failures
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
else
    exit 0
fi