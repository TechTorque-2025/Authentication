#!/bin/bash

# TechTorque Authentication Service - Comprehensive Test Script
# Tests all implemented endpoints

BASE_URL="http://localhost:8081"
TOKEN=""
REFRESH_TOKEN=""
USERNAME="testuser_$(date +%s)"
EMAIL="test_$(date +%s)@example.com"
PASSWORD="testpass123"

echo "=========================================="
echo "TechTorque Authentication Service Tests"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print test results
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
    fi
}

echo -e "${BLUE}Test 1: Health Check${NC}"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health")
if [ "$RESPONSE" = "200" ]; then
    print_result 0 "Health check endpoint"
else
    print_result 1 "Health check endpoint (HTTP $RESPONSE)"
fi
echo ""

echo -e "${BLUE}Test 2: Register New User${NC}"
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$USERNAME\",
    \"email\": \"$EMAIL\",
    \"password\": \"$PASSWORD\"
  }")
echo "Response: $REGISTER_RESPONSE"
if echo "$REGISTER_RESPONSE" | grep -q "registered successfully"; then
    print_result 0 "User registration"
else
    print_result 1 "User registration"
fi
echo ""

echo -e "${BLUE}Test 3: Login (should fail - email not verified)${NC}"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$USERNAME\",
    \"password\": \"$PASSWORD\"
  }")
echo "Response: $LOGIN_RESPONSE"
if echo "$LOGIN_RESPONSE" | grep -q "disabled\|locked\|verified"; then
    print_result 0 "Login blocked for unverified user"
else
    print_result 1 "Login should be blocked"
fi
echo ""

echo -e "${BLUE}Test 4: Resend Verification Email${NC}"
RESEND_RESPONSE=$(curl -s -X POST "$BASE_URL/resend-verification" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$EMAIL\"
  }")
echo "Response: $RESEND_RESPONSE"
if echo "$RESEND_RESPONSE" | grep -q "sent successfully"; then
    print_result 0 "Resend verification email"
else
    print_result 1 "Resend verification email"
fi
echo ""

echo -e "${BLUE}NOTE: Check logs for verification token${NC}"
echo "Look for: 'Verification token for $USERNAME: YOUR_TOKEN'"
echo "Since email is disabled by default, token is logged to console"
echo ""
read -p "Enter verification token from logs (or press Enter to skip): " VERIFY_TOKEN

if [ -n "$VERIFY_TOKEN" ]; then
    echo -e "${BLUE}Test 5: Verify Email${NC}"
    VERIFY_RESPONSE=$(curl -s -X POST "$BASE_URL/verify-email" \
      -H "Content-Type: application/json" \
      -d "{
        \"token\": \"$VERIFY_TOKEN\"
      }")
    echo "Response: $VERIFY_RESPONSE"
    if echo "$VERIFY_RESPONSE" | grep -q "token"; then
        TOKEN=$(echo "$VERIFY_RESPONSE" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
        REFRESH_TOKEN=$(echo "$VERIFY_RESPONSE" | grep -o '"refreshToken":"[^"]*' | cut -d'"' -f4)
        print_result 0 "Email verification"
        echo "JWT Token saved: ${TOKEN:0:20}..."
        echo "Refresh Token saved: ${REFRESH_TOKEN:0:20}..."
    else
        print_result 1 "Email verification"
    fi
else
    echo "Skipping email verification test"
    echo ""
    
    # Login as existing user for remaining tests
    echo -e "${BLUE}Using existing admin account for remaining tests${NC}"
    LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/login" \
      -H "Content-Type: application/json" \
      -d "{
        \"username\": \"admin\",
        \"password\": \"admin123\"
      }")
    if echo "$LOGIN_RESPONSE" | grep -q "token"; then
        TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
        REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"refreshToken":"[^"]*' | cut -d'"' -f4)
        print_result 0 "Admin login"
    else
        print_result 1 "Admin login"
        exit 1
    fi
fi
echo ""

if [ -n "$TOKEN" ]; then
    echo -e "${BLUE}Test 6: Get Current User Profile${NC}"
    PROFILE_RESPONSE=$(curl -s -X GET "$BASE_URL/me" \
      -H "Authorization: Bearer $TOKEN")
    echo "Response: $PROFILE_RESPONSE"
    if echo "$PROFILE_RESPONSE" | grep -q "username"; then
        print_result 0 "Get current user profile"
    else
        print_result 1 "Get current user profile"
    fi
    echo ""

    echo -e "${BLUE}Test 7: Update Profile${NC}"
    UPDATE_RESPONSE=$(curl -s -X PUT "$BASE_URL/profile" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"fullName\": \"Test User\",
        \"phone\": \"+1234567890\",
        \"address\": \"123 Test Street\"
      }")
    echo "Response: $UPDATE_RESPONSE"
    if echo "$UPDATE_RESPONSE" | grep -q "fullName\|username"; then
        print_result 0 "Update profile"
    else
        print_result 1 "Update profile"
    fi
    echo ""

    echo -e "${BLUE}Test 8: Get User Preferences${NC}"
    PREF_GET_RESPONSE=$(curl -s -X GET "$BASE_URL/preferences" \
      -H "Authorization: Bearer $TOKEN")
    echo "Response: $PREF_GET_RESPONSE"
    if echo "$PREF_GET_RESPONSE" | grep -q "emailNotifications"; then
        print_result 0 "Get user preferences"
    else
        print_result 1 "Get user preferences"
    fi
    echo ""

    echo -e "${BLUE}Test 9: Update Preferences${NC}"
    PREF_UPDATE_RESPONSE=$(curl -s -X PUT "$BASE_URL/preferences" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"emailNotifications\": true,
        \"smsNotifications\": false,
        \"appointmentReminders\": true,
        \"language\": \"en\"
      }")
    echo "Response: $PREF_UPDATE_RESPONSE"
    if echo "$PREF_UPDATE_RESPONSE" | grep -q "emailNotifications"; then
        print_result 0 "Update preferences"
    else
        print_result 1 "Update preferences"
    fi
    echo ""

    if [ -n "$REFRESH_TOKEN" ]; then
        echo -e "${BLUE}Test 10: Refresh JWT Token${NC}"
        REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/refresh" \
          -H "Content-Type: application/json" \
          -d "{
            \"refreshToken\": \"$REFRESH_TOKEN\"
          }")
        echo "Response: $REFRESH_RESPONSE"
        if echo "$REFRESH_RESPONSE" | grep -q "token"; then
            print_result 0 "Refresh JWT token"
        else
            print_result 1 "Refresh JWT token"
        fi
        echo ""
    fi
fi

echo -e "${BLUE}Test 11: Forgot Password${NC}"
FORGOT_RESPONSE=$(curl -s -X POST "$BASE_URL/forgot-password" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"admin@techtorque.com\"
  }")
echo "Response: $FORGOT_RESPONSE"
if echo "$FORGOT_RESPONSE" | grep -q "sent successfully"; then
    print_result 0 "Forgot password request"
else
    print_result 1 "Forgot password request"
fi
echo ""

echo -e "${BLUE}Test 12: Admin - List All Users${NC}"
if [ -n "$TOKEN" ]; then
    USERS_RESPONSE=$(curl -s -X GET "$BASE_URL" \
      -H "Authorization: Bearer $TOKEN")
    echo "Response: ${USERS_RESPONSE:0:200}..."
    if echo "$USERS_RESPONSE" | grep -q "username"; then
        print_result 0 "List all users"
    else
        print_result 1 "List all users"
    fi
else
    echo "Skipped - no token available"
fi
echo ""

echo "=========================================="
echo "Tests Complete!"
echo "=========================================="
echo ""
echo "For full testing, ensure:"
echo "1. Service is running on port 8081"
echo "2. Database is accessible"
echo "3. Check logs for verification tokens when email is disabled"
echo ""
echo "To enable email sending:"
echo "  Set EMAIL_ENABLED=true and configure SMTP in application.properties"
