package com.example.project1.config.connect;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry
                .addMapping("/**")
                .allowedOrigins("http://localhost:5173", "http://localhost:3000")
                .allowCredentials(true)
                .allowedHeaders("Authorization", "Content-Type")
                .allowedMethods("GET", "POST", "PUT", "DELETE");
    }
}
