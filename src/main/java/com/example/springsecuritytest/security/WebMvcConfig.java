package com.example.springsecuritytest.security;

import com.example.springsecuritytest.define.AppConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * SpringMVC側のCORS設定
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    protected AppConfig appConfig;

    @Autowired
    WebMvcConfig(AppConfig appConfig) {
        super();
        this.appConfig = appConfig;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(this.appConfig.getFrontendUrl());
    }
}