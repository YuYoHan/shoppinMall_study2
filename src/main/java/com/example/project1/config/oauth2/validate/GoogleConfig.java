package com.example.project1.config.oauth2.validate;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Base64;


@Component
@Slf4j
public class GoogleConfig {

    private Key key;
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String secretKey;


    @PostConstruct
    public void init() {
        this.key = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
    }

    // 소셜 로그인 유저와 토큰이 맞는지 확인
    // ID Token은 사용자 정보와 인증 관련 정보가 담긴 토큰입니다. 보통 ID Token을 검증하여 사용자를 인증하게 됩니다.
    public boolean validateTokenForGoogle(String idToken) {
        try {
            // ID Token 디코딩 및 검증
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(idToken);

            // 클레임에서 필요한 정보를 추출 (예 : 유저 아이디)
            String userEmail = claimsJws.getBody().getSubject();

            // 유저 아이디가 존재하면 유효한 ID Token으로 인정
            if (userEmail != null) {
                return true;
            }
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}
