package com.techtorque.auth_service.exception;

/**
 * Exception thrown when attempting to create a user with a username or email that already exists
 */
public class DuplicateUserException extends RuntimeException {

    public DuplicateUserException(String message) {
        super(message);
    }

    public DuplicateUserException(String message, Throwable cause) {
        super(message, cause);
    }
}
