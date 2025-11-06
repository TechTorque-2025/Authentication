package com.techtorque.auth_service.config;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.techtorque.auth_service.dto.response.ProfilePhotoCacheEntry;
import java.util.concurrent.TimeUnit;

/**
 * Cache configuration for profile photos and user data
 * Implements caching strategy for BLOB data to improve performance
 */
@Configuration
@EnableCaching
public class CacheConfig {

    /**
     * Creates a Guava cache for storing profile photos in memory
     * - Cache size: 100 users maximum
     * - TTL: 1 hour
     * - Auto-refresh: Cache is invalidated when photo is updated
     */
    @Bean
    public Cache<Long, byte[]> profilePhotoCache() {
        return CacheBuilder.newBuilder()
                .maximumSize(100)
                .expireAfterWrite(1, TimeUnit.HOURS)
                .build();
    }

    /**
     * Creates a Guava cache for storing profile photo metadata
     * - Cache size: 100 users maximum
     * - TTL: 1 hour
     * - Stores: userId -> (lastUpdated timestamp, MIME type, size)
     */
    @Bean
    public Cache<Long, ProfilePhotoCacheEntry> profilePhotoMetadataCache() {
        return CacheBuilder.newBuilder()
                .maximumSize(100)
                .expireAfterWrite(1, TimeUnit.HOURS)
                .build();
    }
}
