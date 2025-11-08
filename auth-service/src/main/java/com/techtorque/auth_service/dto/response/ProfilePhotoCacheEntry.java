package com.techtorque.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Cache entry metadata for profile photos
 * Used for cache validation and ETag generation
 * Stores size, MIME type, and last update timestamp
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProfilePhotoCacheEntry {
    public Long timestamp;
    public String mimeType;
    public Long size;
}

