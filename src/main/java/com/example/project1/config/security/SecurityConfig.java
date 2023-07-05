package com.example.project1.config.security;

import com.example.project1.config.jwt.JwtAccessDeniedHandler;
import com.example.project1.config.jwt.JwtAuthenticationEntryPoint;
import com.example.project1.config.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {

    private final JwtProvider jwtProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 스프링 시큐리티에서 제공하는 로그인 페이지를 안쓰기 위해
                .httpBasic().disable()
                // JWt 방식을 제대로 쓰려고 하면 프론트엔드가 분리된 환경을 가정하고 해야합니다.
                .csrf().disable()
                .formLogin().disable()
                // JWT 방식은 세션저장을 사용하지 않기 때문에 꺼줍니다.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http
                .authorizeRequests()
                .antMatchers("/api/v1/users/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/users/signUp")
                .permitAll()
                .antMatchers("/api/v1/users/login")
                .permitAll()
                .anyRequest().permitAll();

        http
                // JWT Token을 위한 Filter를 아래에서 만들어 줄건데,
                // 이 Filter를 어느위치에서 사용하겠다고 등록을 해주어야 Filter가 작동이 됩니다.
                // security 로직에 JwtFilter 등록
                // .addFilterBefore(new JwtAuthenticationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
                .apply(new JwtSecurityConfig(jwtProvider));

        // 에러 방지
        http
                .exceptionHandling()
                .authenticationEntryPoint(new JwtAuthenticationEntryPoint())
                .accessDeniedHandler(new JwtAccessDeniedHandler());

        return http.build();
    }
}
