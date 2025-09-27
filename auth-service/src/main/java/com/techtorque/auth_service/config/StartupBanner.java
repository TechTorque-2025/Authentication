package com.techtorque.auth_service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Prints a small startup banner/message when the application is ready.
 * Only prints when running with the 'dev' profile and when enabled via config.
 */
@Component
public class StartupBanner {

    private static final Logger logger = LoggerFactory.getLogger(StartupBanner.class);

    private final Environment env;

    private final boolean bannerEnabled;

    public StartupBanner(Environment env, @Value("${app.banner.enabled:true}") boolean bannerEnabled) {
        this.env = env;
        this.bannerEnabled = bannerEnabled;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        if (!bannerEnabled) {
            return;
        }

        String[] active = env.getActiveProfiles();
        boolean isDev = false;
        for (String p : active) {
            if ("dev".equalsIgnoreCase(p)) {
                isDev = true;
                break;
            }
        }

        if (isDev) {
            String[] banner = new String[] {
                    "========================================",
                    "=   DEVELOPMENT MODE - TECHTORQUE     =",
                    "=   Seeding development users now     =",
                    "========================================"
            };

            for (String line : banner) {
                // Log and also print to stdout for immediate CLI visibility
                logger.info(line);
                System.out.println(line);
            }
        } else {
            logger.info("Application started with profiles: {}", String.join(",", active));
        }
    }
}
