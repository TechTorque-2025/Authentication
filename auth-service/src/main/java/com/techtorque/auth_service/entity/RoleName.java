package com.techtorque.auth_service.entity;

/**
 * Enum defining the three roles in the system
 * ADMIN - Full system access
 * EMPLOYEE - Limited access for staff operations  
 * CUSTOMER - Access to customer-specific features
 */
public enum RoleName {
    ADMIN("Administrator - Full system access"),
    EMPLOYEE("Employee - Limited system access for staff operations"), 
    CUSTOMER("Customer - Access to customer-specific features");

    private final String description;

    RoleName(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}