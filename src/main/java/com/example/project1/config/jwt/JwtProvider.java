package com.example.project1.config.jwt;

import com.example.project1.domain.jwt.TokenDTO;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Log4j2
@Component
public class JwtProvider {
    private static final String AUTHORITIES_KEY = "auth";
    @Value("${jwt.access.expiration}")
    private long accessTokenExpiration;
    @Value("${jwt.refresh.expiration}")
    private long refreshTokenExpiration;
    private Key key;

    public JwtProvider(@Value("${jwt.secret_key}") String secretKey) {
        byte[] secretByteKey = Base64.getDecoder().decode(secretKey);
        this.key = Keys.hmacShaKeyFor(secretByteKey);
    }


    public TokenDTO createToken(String email, List<GrantedAuthority> authorities ) {
        // 클레임(Claims)에 유저 권한 등록
        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        // 클레임에 유저 이름(이메일 또는 id) 등록
        claims.put("sub", email);

        // JWT 발급 시간
        Date now = new Date(System.currentTimeMillis());

        // Access Token 만료 시간
        Date accessTokenExpire = new Date(now.getTime() + accessTokenExpiration);
        String accessToken = Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuedAt(now)
                .expiration(accessTokenExpire)
                .signWith(key)  // key 객체 사용
                .compact();

        // Refresh Token 생성
        Date refreshTokenExpire = new Date(now.getTime() + refreshTokenExpiration);
        String refreshToken = Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuedAt(now)
                .expiration(refreshTokenExpire)
                .signWith(key)  // key 객체 사용
                .compact();

        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .email(email)
                .build();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException | IllegalArgumentException e) {
            log.error("잘못된 JWT 설명 \n info={}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("만료된 JWT 설명 \n info={}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("지원되지 않는 JWT 설명 \n info={}", e.getMessage());
        }
        return false;
    }

    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);

        if(claims.get("auth") == null) {
            log.error("권한 정보가 없는 토큰입니다.");
            throw new AccessDeniedException("권한 정보가 없는 토큰입니다.");
        }

        List<String> authority = (List<String>) claims.get(AUTHORITIES_KEY);
        Collection<? extends GrantedAuthority> authorities =
                authority.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        UserDetails userDetails = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(userDetails, token, authorities);
    }

    private Claims parseClaims(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.error("만료된 JWT 설명 \n info={}", e.getMessage());
            return e.getClaims();
        }
    }
    private String checkToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }
}
