package com.slim.company.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FileStorageConfig {
    @Value("${UPLOAD_DIR}")
    private String uploadDir;

    @Bean
    public String uploadDir() {
        return this.uploadDir;
    }
}
