package com.example.project1.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        String idForEncode = "bcrypt";
        Map<String, PasswordEncoder> encoder = new HashMap<>();
        encoder.put(idForEncode, new BCryptPasswordEncoder());
        return new DelegatingPasswordEncoder(idForEncode, encoder);
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(auth -> auth.disable());

        http
                .formLogin(auth -> auth.disable())
                .httpBasic(auth -> auth.disable());

        // 경로별 인가 작업
        http
                .authorizeHttpRequests(auth -> auth
                        .regexMatchers("/login", "/", "/join").permitAll()
                        .regexMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        // 세션 설정
        http
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }
}
