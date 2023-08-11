package com.example.project1.config.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 클라이언트 요청 시 JWT 인증을 하기 위해 설치하는 커스텀 필터로
// UsernamePasswordAuthenticationFiler 이전에 실행된다.
// 이전에 실행된다는 뜻은 JwtAuthenticationFilter 를 통과하면
// UsernamePasswordAuthenticationFilter 이후의 필터는 통과한 것으로 본다는 뜻이다.
// 쉽게 말해서, Username + Password 를 통한 인증을 Jwt 를 통해 수행한다는 것이다.

// JWT 방식은 세션과 다르게 Filter 하나를 추가해야 합니다.
// 이제 사용자가 로그인을 했을 때, Request 에 가지고 있는 Token 을 해석해주는 로직이 필요합니다.
// 이 역할을 해주는것이 JwtAuthenticationFilter입니다.
// 세부 비즈니스 로직들은 TokenProvider에 적어둡니다. 일종의 service 클래스라고 생각하면 편합니다.
// 1. 사용자의 Request Header에 토큰을 가져옵니다.
// 2. 해당 토큰의 유효성 검사를 실시하고 유효하면
// 3. Authentication 인증 객체를 만들고
// 4. ContextHolder에 저장해줍니다.
// 5. 해당 Filter 과정이 끝나면 이제 시큐리티에 다음 Filter로 이동하게 됩니다.

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER_AUTHORIZATION = "Authorization";
    private final JwtProvider jwtProvider;

    // doFilter는 토큰의 인증정보를 SecurityContext에 저장하는 역할 수행
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        // Request Header에서 JWT 토큰을 추출
        //  요청 헤더에서 JWT 토큰을 추출하는 역할
        String jwt = resolveToken(httpServletRequest);
        //  jwt :
        // eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ6eHp6NDVAbmF2ZXIuY29tIiwiaWF
        // 0IjoxNjg5OTQ0OTk0LCJhdXRoIjoiIiwiZXhwIjoxNjg5OTQ1MzU0fQ.qyR2bJMDmNb1iv
        // q6a4W55dGBmyFEzaENN1-F7qPlJKw
        log.info("jwt in JwtAuthenticationFilter : " + jwt);
        String requestURI = httpServletRequest.getRequestURI();
        // requestURI/api/v1/users/1
        log.info("requestURI in JwtAuthenticationFilter : " + requestURI);

        if (StringUtils.hasText(jwt) && jwtProvider.validateToken(jwt)) {
            // 토큰이 유효할 경우 토큰에서 Authentication 객체를 가지고 와서 SecurityContext에 저장
            Authentication authentication = jwtProvider.getAuthentication(jwt);
            // UsernamePasswordAuthenticationToken
            // [Principal=org.springframework.security.core.userdetails.User
            // [Username=zxzz45@naver.com, Password=[PROTECTED], Enabled=true, AccountNonExpired=true,
            // credentialsNonExpired=true, AccountNonLocked=true, Granted Authorities=[ROLE_USER]],
            // Credentials=[PROTECTED], Authenticated=true, Details=null,
            // Granted Authorities=[ROLE_USER]]
            log.info("authentication in JwtAuthenticationFilter : " + authentication);
            // Spring Security의 SecurityContextHolder를 사용하여 현재 인증 정보를 설정합니다.
            // 이를 통해 현재 사용자가 인증된 상태로 처리됩니다.
            // 위에서 jwtProvider.getAuthentication(jwt)가 반환이 UsernamePasswordAuthenticationToken로
            // SecurityContext에 저장이 되는데 SecurityContextHolder.getContext().setAuthentication(authentication);
            // 처리를 하는 이유는 다음과 같다.
            /*
             *   1.  인증 정보 검증: JWT 토큰이나 다른 인증 정보를 사용하여 사용자를 식별하고
             *       권한을 확인하기 위해서는 토큰을 해독하여 사용자 정보와 권한 정보를 추출해야 합니다.
             *       이 역할은 jwtProvider.getAuthentication(jwt)에서 수행됩니다.
             *       이 메서드는 JWT 토큰을 분석하여 사용자 정보와 권한 정보를 추출하고, 해당 정보로 인증 객체를 생성합니다.
             *
             *   2.  인증 정보 저장:
             *       검증된 인증 객체를 SecurityContextHolder.getContext().setAuthentication(authentication);를
             *       사용하여 SecurityContext에 저장하는 이유는, Spring Security에서 현재 사용자의 인증 정보를
             *       전역적으로 사용할 수 있도록 하기 위함입니다. 이렇게 하면 다른 부분에서도 현재 사용자의 인증 정보를 사용할 수 있게 되며,
             *       Spring Security가 제공하는 @AuthenticationPrincipal 어노테이션을 통해 현재 사용자 정보를 편리하게 가져올 수 있습니다.
             * */
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.info("Security Context에 인증 정보를 저장했습니다. 정보 : {}", authentication.getName());
        } else {
            log.debug("유효한 JWT 토큰이 없습니다. uri : {}", requestURI);
        }
        filterChain.doFilter(request, response);
    }


    // Request Header 에서 토큰 정보를 꺼내오기 위한 메소드
    // HEADER_AUTHORIZATION로 정의된 헤더 이름을 사용하여 토큰을 찾고,
    // 토큰이 "Bearer "로 시작하는 경우에만 실제 토큰 값을 반환
    private String resolveToken(HttpServletRequest httpServletRequest) {
        String bearerToken = httpServletRequest.getHeader(HEADER_AUTHORIZATION);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        } else if (StringUtils.hasText(bearerToken)) {
            return bearerToken;
        } else {
            return null;
        }
    }
}
