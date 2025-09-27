package com.techtorque.auth_service.entity;

/**
 * Constants class containing all permission names used in the system
 * This centralizes permission management and prevents typos
 */
public class PermissionConstants {
    
    // ============ ADMIN PERMISSIONS ============
    // User management permissions - only admins can create/update/delete users
    public static final String CREATE_EMPLOYEE = "CREATE_EMPLOYEE"; // Only admins can create employees
    public static final String CREATE_ADMIN = "CREATE_ADMIN"; // Only admins can create other admins
    public static final String UPDATE_USER = "UPDATE_USER"; 
    public static final String DELETE_USER = "DELETE_USER";
    public static final String VIEW_ALL_USERS = "VIEW_ALL_USERS";
    
    // Role management - only admins can assign/remove roles
    public static final String MANAGE_ROLES = "MANAGE_ROLES";
    
    // System administration
    public static final String SYSTEM_ADMIN = "SYSTEM_ADMIN";
    
    // ============ EMPLOYEE PERMISSIONS ============  
    // Employee can view and update customer data for support purposes
    public static final String VIEW_CUSTOMER_DATA = "VIEW_CUSTOMER_DATA";
    public static final String UPDATE_CUSTOMER_DATA = "UPDATE_CUSTOMER_DATA";
    
    // Employee can access business reports
    public static final String VIEW_REPORTS = "VIEW_REPORTS";
    
    // ============ CUSTOMER PERMISSIONS ============
    // Basic profile management - all users can view/update their own profile
    public static final String VIEW_OWN_PROFILE = "VIEW_OWN_PROFILE";
    public static final String UPDATE_OWN_PROFILE = "UPDATE_OWN_PROFILE";
    
    // Customer-specific actions
    public static final String PLACE_ORDER = "PLACE_ORDER";
    public static final String VIEW_ORDER_HISTORY = "VIEW_ORDER_HISTORY";
}