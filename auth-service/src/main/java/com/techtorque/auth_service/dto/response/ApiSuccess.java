package com.techtorque.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApiSuccess {
    private int status;
    private String message;
    private Object data;
    private LocalDateTime timestamp = LocalDateTime.now();

    public static ApiSuccess of(String message) {
        return new ApiSuccess(200, message, null, LocalDateTime.now());
    }

    public static ApiSuccess of(String message, Object data) {
        return new ApiSuccess(200, message, data, LocalDateTime.now());
    }
}
