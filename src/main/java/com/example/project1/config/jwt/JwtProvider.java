package com.example.project1.config.jwt;

import com.example.project1.domain.jwt.TokenDTO;
import com.example.project1.repository.member.MemberRepository;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.security.Keys;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtProvider {

    private static final String AUTHORITIES_KEY = "auth";

    @Value("${jwt.access.expiration}")
    private long accessTokenTime;

    @Value("${jwt.refresh.expiration}")
    private long refreshTokenTime;

    private Key key;


    public JwtProvider( @Value("${jwt.secret_key}") String secret_key) {
        byte[] secretByteKey = DatatypeConverter.parseBase64Binary(secret_key);
        this.key = Keys.hmacShaKeyFor(secretByteKey);
    }

//     유저 정보를 가지고 AccessToken, RefreshToken 을 생성하는 메소드
    public TokenDTO createToken(Authentication authentication) {

        // 권한 가져오기
        //  authentication 객체에서 권한 정보(GrantedAuthority)를 가져와 문자열 형태로 변환한 후,
        //  쉼표로 구분하여 조인한 결과를 authorities 변수에 저장합니다. 따라서 authorities는 권한 정보를 문자열 형태로 가지게 됩니다.
        // 권한 정보를 문자열로 변환하여 클레임에 추가하는 방식
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date now2 = new Date();

        // AccessToken 생성
        Date accessTokenExpire = new Date(now + this.accessTokenTime);
        String accessToken = Jwts.builder()
                // 내용 sub : 유저의 이메일
                // 토큰 제목
                .setSubject(authentication.getName())
                .setIssuedAt(now2)
                // 클레임 id : 유저 ID
                .claim(AUTHORITIES_KEY, authorities)
                // 내용 exp : 토큰 만료 시간, 시간은 NumericDate 형식(예: 1480849143370)으로 하며
                // 항상 현재 시간 이후로 설정합니다.
                .setExpiration(accessTokenExpire)
                // 서명 : 비밀값과 함께 해시값을 ES256 방식으로 암호화
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        log.info("accessToken : " + accessToken);

        // RefreshToken 생성
        Date refreshTokenExpire = new Date(now + this.refreshTokenTime);
        String refreshToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .setIssuedAt(now2)
                .setExpiration(refreshTokenExpire)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        log.info("refreshToken : " + refreshToken);

        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                // principalDeatails에서 getUserName 메소드가 반환한 것을 담아준다.
                // 이메일을 반환하도록 구성했으니 이메일이 반환됩니다.
                .userEmail(authentication.getName())
                .build();
    }

    // 소셜 로그인 성공시 JWT 발급
    public TokenDTO createToken2(UserDetails userDetails) {
        long now = (new Date()).getTime();
        Date now2 = new Date();

        // userDetails.getAuthorities()는 사용자의 권한(authorities) 정보를 가져오는 메서드입니다.
        // claims.put("roles", userDetails.getAuthorities()) 코드는 사용자의 권한 정보를 클레임에 추가하는 것입니다.
        // 클레임에는 "roles"라는 키로 사용자의 권한 정보가 저장되며, 해당 권한 정보는 JWT의 페이로드 부분에 포함됩니다.
        Claims claims = Jwts.claims().setSubject(userDetails.getUsername());
        claims.put("roles", userDetails.getAuthorities());

        // access token
        Date accessTokenExpire = new Date(now + this.accessTokenTime);
        String accessToken = Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setClaims(claims)
                .setIssuedAt(now2)
                .setExpiration(accessTokenExpire)
                .signWith(key,SignatureAlgorithm.HS256)
                .compact();

        // RefreshToken 생성
        Date refreshTokenExpire = new Date(now + this.refreshTokenTime);
        String refreshToken = Jwts.builder()
                .setIssuedAt(now2)
                .setClaims(claims)
                .setExpiration(refreshTokenExpire)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .userEmail(userDetails.getUsername())
                .build();
    }


    // 위에께 원래 되는데 에러가 발생해서 다른 방법을 찾는 중
    // v2임
//    public  TokenDTO createToken(String userEmail) {
//        long now = (new Date()).getTime();
//        Date now2 = new Date();
//
//
//
//        // access token 생성
//        Date accessTokenExpire = new Date(now + this.accessTokenTime);
//        String accessToken = Jwts.builder()
//                .setIssuedAt(now2)
//                .setSubject(userEmail)
//                .claim(AUTHORITIES_KEY, authorities)
//                .setExpiration(accessTokenExpire)
//                .signWith(key, SignatureAlgorithm.HS256)
//                .compact();
//
//        // refreshToken 생성
//        Date refreshTokenExpire = new Date(now + this.refreshTokenTime);
//        String refreshToken = Jwts.builder()
//                .setSubject(userEmail)
//                .claim(AUTHORITIES_KEY, authorities)
//                .setExpiration(refreshTokenExpire)
//                .signWith(key, SignatureAlgorithm.HS256)
//                .compact();
//
//        return TokenDTO.builder()
//                .grantType("Bearer ")
//                .accessToken(accessToken)
//                .refreshToken(refreshToken)
//                .build();
//    }

    // accessToken 생성
    // 리프레시 토큰을 사용하여 새로운 액세스 토큰을 생성하는 로직을 구현
    public TokenDTO createAccessToken(String refreshToken, List<GrantedAuthority> authorities) {
        Long now = (new Date()).getTime();
        Date now2 = new Date();
        Date accessTokenExpire = new Date(now + this.accessTokenTime);

        String userEmail = extractUserEmailFromToken(refreshToken);

        String accessToken = Jwts.builder()
                .setIssuedAt(now2)
                .setSubject(userEmail)
                .setExpiration(accessTokenExpire)
                .claim(AUTHORITIES_KEY, authorities )
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        log.info("accessToken : " + accessToken);

        return TokenDTO.builder()
                .grantType("Bearer ")
                .accessToken(accessToken)
                .userEmail(userEmail)
                .build();
    }

    // 리프레시 토큰의 유효성을 검증하는 로직을 구현
    // 예를 들어, 토큰 서명 검증 및 만료 시간 확인 등을 수행
    public boolean validateRefreshToken(String refreshToken) {
        try {
            // 토큰의 유효성을 검증하는 로직을 구현
            // 예를 들어, 토큰의 서명을 확인하고 만료 시간을 검사합니다.
            // 유효한 토큰인 경우 true를 반환하고, 그렇지 않은 경우 false를 반환합니다.
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(refreshToken);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    // 리프레시 토큰에서 사용자 이메일을 추출하는 로직을 구현
    // 예를 들어, 토큰의 특정 클레임에서 사용자 이메일을 추출하여 반환
    public String extractUserEmailFromToken(String refreshToken) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(refreshToken).getBody();
        // 사용자 이메일을 추출하는 로직을 구현하여 결과를 반환
        return claims.getSubject();
    }


    // JWT 토큰을 복호화하여 토큰에 들어있는 정보를 꺼내는 코드
    // 토큰으로 클레임을 만들고 이를 이용해 유저 객체를 만들어서 최종적으로 authentication 객체를 리턴
    // 인증 정보 조회
    public Authentication getAuthentication(String token) {
        // 토큰 복호화 메소드
        Claims claims = parseClaims(token);

        if(claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }


        // 클레임 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails 객체를 만들어서 Authentication 리턴
        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    private Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.info("ExpiredJwtException : " + e.getMessage());
            log.info("ExpiredJwtException : " + e.getClaims());

            return e.getClaims();
        }
    }

    // 토큰의 유효성 검증을 수행
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        }catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }


}
