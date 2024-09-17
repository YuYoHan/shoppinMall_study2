package com.example.project1.config.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Log4j2
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    public static final String HEADER_AUTHORIZATION = "Authorization";
    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = resolveToken(httpServletRequest);
        if(token != null && jwtProvider.validateToken(token)) {
            Authentication authentication = jwtProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            log.error("유효한 토큰이 없습니다.");
        }
        filterChain.doFilter(request, response);

    }

    private String resolveToken(HttpServletRequest httpServletRequest) {
        String token = httpServletRequest.getHeader(HEADER_AUTHORIZATION);

        if(StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            return token.substring(7);
        } else if(StringUtils.hasText(token)) {
            return token;
        } else {
            return null;
        }
    }
}
