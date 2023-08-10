package com.example.project1.config.security;

import com.example.project1.config.jwt.JwtAuthenticationFilter;
import com.example.project1.config.jwt.JwtProvider;
import com.example.project1.config.oauth2.validate.GoogleConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final JwtProvider jwtProvider;
    private final GoogleConfig googleConfig;


    // JwtAuthenticationFilter 가 일반 로그인에 대한 토큰 검증을 처리하고,
    // 검증에 실패한 경우 SocialTokenAuthenticationFilter 에서 소셜 로그인 토큰에 대한 검증을 수행
    @Override
    public void configure(HttpSecurity http) throws Exception {
        // JwtAuthenticationFilter가 일반 로그인에 대한 토큰 검증을 처리
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtProvider, googleConfig);

        http
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
