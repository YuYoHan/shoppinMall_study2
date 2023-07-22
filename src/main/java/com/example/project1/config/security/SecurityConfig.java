package com.example.project1.config.security;

import com.example.project1.config.jwt.JwtAccessDeniedHandler;
import com.example.project1.config.jwt.JwtAuthenticationEntryPoint;
import com.example.project1.config.jwt.JwtProvider;
import com.example.project1.config.oauth2.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
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
@RequiredArgsConstructor
@EnableWebSecurity
// @EnableGlobalMethodSecurity 어노테이션은 Spring Security에서 메서드 수준의 보안 설정을 활성화하는데 사용되는 어노테이션입니다.
//@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {

    private final JwtProvider jwtProvider;
    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 스프링 시큐리티에서 제공하는 로그인 페이지를 안쓰기 위해
                .httpBasic().disable()
                // JWt 방식을 제대로 쓰려고 하면 프론트엔드가 분리된 환경을 가정하고 해야합니다.
                .csrf().disable()
                .formLogin().disable()
                .logout().disable()
                // JWT 방식은 세션저장을 사용하지 않기 때문에 꺼줍니다.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http
                .authorizeRequests()
                .antMatchers("/api/v1/boards/write")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/boards/modify")
                .access("hasRole('ROLE_USER')")
                .antMatchers("/api/v1/boards/remove")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                // /success-oauth 엔드포인트에 대해 인증된 사용자만 접근 가능하도록 설정
//                .antMatchers("/success-oauth").authenticated()
                .antMatchers("/swagger-resources/**").permitAll()
                        .antMatchers("/swagger-ui/**").permitAll()
                        .antMatchers("/api/v1/users/**").permitAll();

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

        // oauth2
        http
                // oauth2Login() 메서드는 OAuth 2.0 프로토콜을 사용하여 소셜 로그인을 처리하는 기능을 제공합니다.
                .oauth2Login()
//                .defaultSuccessUrl("/success-oauth")
                    // OAuth2 로그인 성공 이후 사용자 정보를 가져올 때 설정 담당
                    .userInfoEndpoint()
                        // OAuth2 로그인 성공 시, 후작업을 진행할 서비스
                        .userService(principalOauth2UserService)
                    .and()
                        .defaultSuccessUrl("/success-oauth");

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        String idForEncode = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put(idForEncode, new BCryptPasswordEncoder());

        return new DelegatingPasswordEncoder(idForEncode, encoders);
    }
}
