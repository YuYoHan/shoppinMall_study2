package com.example.project1.config.jwt;

import com.example.project1.domain.jwt.TokenDTO;
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
import java.util.*;
import java.util.stream.Collectors;

// 일반 로그인을 하면 PrincipalDetails 정보를 가지고 JWT를 만들어준다.
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
    public TokenDTO createToken(Authentication authentication, List<GrantedAuthority> authorities) {
        //  UsernamePasswordAuthenticationToken
        //  [Principal=zxzz45@naver.com, Credentials=[PROTECTED], Authenticated=false, Details=null, Granted Authorities=[]]
        // 여기서 Authenticated=false는 아직 정상임
        // 이 시점에서는 아직 실제로 인증이 이루어지지 않았기 때문에 Authenticated 속성은 false로 설정
        // 인증 과정은 AuthenticationManager와 AuthenticationProvider에서 이루어지며,
        // 인증이 성공하면 Authentication 객체의 isAuthenticated() 속성이 true로 변경됩니다.
        log.info("authentication in JwtProvider : " + authentication);

        // userType in JwtProvider : ROLE_USER
        log.info("userType in JwtProvider : " + authorities);

        // 권한 가져오기
        //  authentication 객체에서 권한 정보(GrantedAuthority)를 가져와 문자열 형태로 변환한 후,
        //  쉼표로 구분하여 조인한 결과를 authorities 변수에 저장합니다. 따라서 authorities는 권한 정보를 문자열 형태로 가지게 됩니다.
        // 권한 정보를 문자열로 변환하여 클레임에 추가하는 방식
//        String authorities = authentication.getAuthorities().stream()
//                .map(GrantedAuthority::getAuthority)
//                .collect(Collectors.joining(","));

        Map<String, Object> claims = new HashMap<>();
        claims.put(AUTHORITIES_KEY, authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        claims.put("sub", authentication.getName());


        // claims in JwtProvider : {auth=[ROLE_USER]}
        log.info("claims in JwtProvider : " + claims);
        // authentication.getName() in JwtProvider : zxzz45@naver.com
        log.info("authentication.getName() in JwtProvider : " + authentication.getName());

        long now = (new Date()).getTime();
        Date now2 = new Date();



        // AccessToken 생성
        Date accessTokenExpire = new Date(now + this.accessTokenTime);
        String accessToken = Jwts.builder()
                // 내용 sub : 유저의 이메일
                // 토큰 제목
                // JWT의 "sub" 클레임을 설정하는 메서드입니다.
                // "sub" 클레임은 일반적으로 사용자를 식별하는 용도로 사용되며,
                // 이메일과 같은 사용자의 고유한 식별자를 담고 있을 수 있습니다.
                .setIssuedAt(now2)
                // 클레임 id : 유저 ID
//                .claim(AUTHORITIES_KEY, authorities)
                .setClaims(claims)
                // 내용 exp : 토큰 만료 시간, 시간은 NumericDate 형식(예: 1480849143370)으로 하며
                // 항상 현재 시간 이후로 설정합니다.
                .setExpiration(accessTokenExpire)
                // 서명 : 비밀값과 함께 해시값을 ES256 방식으로 암호화
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        Claims claims1 =
                Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(accessToken)
                        .getBody();
        String subject1 = claims1.getSubject();
        // claims subject 확인 in JwtProvider : zxzz45@naver.com
        log.info("★claims access subject 확인 in JwtProvider : " + subject1);


        // accessToken in JwtProvider : eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ6eHp6NDVAbmF2ZXIuY2
        // 9tIiwiaWF0IjoxNjg5OTk1MzM3LCJhdXRoIjoiUk9MRV9VU0VSIiwiZXhwIjoxNjkzNTk1MzM3fQ.2_2PR-A
        // X9N0jKDyA7LpK7xRRBZBYZ17_f8Jq2TY4ny8
        log.info("accessToken in JwtProvider : " + accessToken);

        // claim에서 auth 확인 in JwtProvider : ROLE_USER
        log.info("claim에서 accessToken에 담김 auth 확인 in JwtProvider : " + claims);

        // RefreshToken 생성
        Date refreshTokenExpire = new Date(now + this.refreshTokenTime);
        String refreshToken = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now2)
                .setExpiration(refreshTokenExpire)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        Claims claims2 =
                Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(refreshToken)
                        .getBody();
        String subject2 = claims2.getSubject();
        // claims subject 확인 in JwtProvider : zxzz45@naver.com
        log.info("★claims refreshToken subject 확인 in JwtProvider : " + subject2);

        log.info("refreshToken in JwtProvider : " + refreshToken);
        log.info("claim에서 refreshToken에 담긴 auth 확인 in JwtProvider : " + claims);

        TokenDTO tokenDTO= TokenDTO.builder()
                .grantType("Bearer ")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenTime(accessTokenExpire)
                .refreshTokenTime(refreshTokenExpire)
                // principalDeatails에서 getUserName 메소드가 반환한 것을 담아준다.
                // 이메일을 반환하도록 구성했으니 이메일이 반환됩니다.
                .userEmail(authentication.getName())
                .build();

        log.info("tokenDTO in JwtProvider : " + tokenDTO);

        return tokenDTO;
    }

    // 소셜 로그인 성공시 JWT 발급
    public TokenDTO createTokenForOAuth2(String userEmail, List<GrantedAuthority> authorities) {

        // userType in JwtProvider : ROLE_USER
        log.info("userEmail in JwtProvider : " + userEmail);
        log.info("authorities in JwtProvider : " + authorities);

        // 권한 가져오기
        //  authentication 객체에서 권한 정보(GrantedAuthority)를 가져와 문자열 형태로 변환한 후,
        //  쉼표로 구분하여 조인한 결과를 authorities 변수에 저장합니다. 따라서 authorities는 권한 정보를 문자열 형태로 가지게 됩니다.
        // 권한 정보를 문자열로 변환하여 클레임에 추가하는 방식
//        String authorities = authentication.getAuthorities().stream()
//                .map(GrantedAuthority::getAuthority)
//                .collect(Collectors.joining(","));

        Map<String, Object> claims = new HashMap<>();
        claims.put(AUTHORITIES_KEY, authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        claims.put("sub", userEmail);


        // claims in JwtProvider : {auth=[ROLE_USER]}
        log.info("claims in JwtProvider : " + claims);
        // authentication.getName() in JwtProvider : zxzz45@naver.com
        log.info("claims.get(\"sub\") in JwtProvider : " + claims.get("sub"));

        long now = (new Date()).getTime();
        Date now2 = new Date();



        // AccessToken 생성
        Date accessTokenExpire = new Date(now + this.accessTokenTime);
        String accessToken = Jwts.builder()
                // 내용 sub : 유저의 이메일
                // 토큰 제목
                // JWT의 "sub" 클레임을 설정하는 메서드입니다.
                // "sub" 클레임은 일반적으로 사용자를 식별하는 용도로 사용되며,
                // 이메일과 같은 사용자의 고유한 식별자를 담고 있을 수 있습니다.
                .setIssuedAt(now2)
                // 클레임 id : 유저 ID
//                .claim(AUTHORITIES_KEY, authorities)
                .setClaims(claims)
                // 내용 exp : 토큰 만료 시간, 시간은 NumericDate 형식(예: 1480849143370)으로 하며
                // 항상 현재 시간 이후로 설정합니다.
                .setExpiration(accessTokenExpire)
                // 서명 : 비밀값과 함께 해시값을 ES256 방식으로 암호화
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        Claims claims1 = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(accessToken)
                .getBody();
        String subject1 = claims1.getSubject();
        // claims subject 확인 in JwtProvider : zxzz45@naver.com
        log.info("★claims access subject 확인 in JwtProvider : " + subject1);


        // accessToken in JwtProvider : eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ6eHp6NDVAbmF2ZXIuY2
        // 9tIiwiaWF0IjoxNjg5OTk1MzM3LCJhdXRoIjoiUk9MRV9VU0VSIiwiZXhwIjoxNjkzNTk1MzM3fQ.2_2PR-A
        // X9N0jKDyA7LpK7xRRBZBYZ17_f8Jq2TY4ny8
        log.info("accessToken in JwtProvider : " + accessToken);

        // claim에서 auth 확인 in JwtProvider : ROLE_USER
        log.info("claim에서 accessToken에 담김 auth 확인 in JwtProvider : " + claims);

        // RefreshToken 생성
        Date refreshTokenExpire = new Date(now + this.refreshTokenTime);
        String refreshToken = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now2)
                .setExpiration(refreshTokenExpire)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        Claims claims2 = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(refreshToken)
                .getBody();
        String subject2 = claims2.getSubject();
        // claims subject 확인 in JwtProvider : zxzz45@naver.com
        log.info("★claims refreshToken subject 확인 in JwtProvider : " + subject2);

        log.info("refreshToken in JwtProvider : " + refreshToken);
        log.info("claim에서 refreshToken에 담긴 auth 확인 in JwtProvider : " + claims);

        TokenDTO tokenDTO= TokenDTO.builder()
                .grantType("Bearer ")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenTime(accessTokenExpire)
                .refreshTokenTime(refreshTokenExpire)
                // principalDeatails에서 getUserName 메소드가 반환한 것을 담아준다.
                // 이메일을 반환하도록 구성했으니 이메일이 반환됩니다.
                .userEmail(userEmail)
                .build();

        log.info("tokenDTO in JwtProvider : " + tokenDTO);

        return tokenDTO;
    }

    // accessToken 생성
    // 리프레시 토큰을 사용하여 새로운 액세스 토큰을 생성하는 로직을 구현
    public TokenDTO createAccessToken(String userEmail, List<GrantedAuthority> authorities) {
        Long now = (new Date()).getTime();
        Date now2 = new Date();
        Date accessTokenExpire = new Date(now + this.accessTokenTime);

        log.info("authorities : " + authorities);

        Map<String, Object> claims = new HashMap<>();
        claims.put(AUTHORITIES_KEY, authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        // setSubject이다.
        // 클레임에 subject를 넣는것
        claims.put("sub", userEmail);

        log.info("claims : " + claims);

        String accessToken = Jwts.builder()
                .setIssuedAt(now2)
                .setClaims(claims)
                .setExpiration(accessTokenExpire)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        log.info("accessToken in JwtProvider : " + accessToken);

        Claims claims2 = Jwts.parserBuilder()
                        .setSigningKey(key)
                                .build()
                                        .parseClaimsJws(accessToken)
                                                .getBody();

        String subject = claims2.getSubject();
        // claims subject 확인 in JwtProvider : zxzz45@naver.com
        log.info("★claims subject 확인 in JwtProvider : " + subject);

//        log.info("claim에서 accessToken에 담김 auth 확인 in JwtProvider : " + auth);

        TokenDTO tokenDTO = TokenDTO.builder()
                .grantType("Bearer ")
                .accessToken(accessToken)
                .userEmail(userEmail)
                .accessTokenTime(accessTokenExpire)
                .build();

        log.info("tokenDTO in JwtProvider : " + tokenDTO);
        return tokenDTO;
    }


    // JWT 토큰을 복호화하여 토큰에 들어있는 정보를 꺼내는 코드
    // 토큰으로 클레임을 만들고 이를 이용해 유저 객체를 만들어서 최종적으로 authentication 객체를 리턴
    // 인증 정보 조회
    // 이거는 일반 로그인 시 JWT 발급받은 것을 헤더에 보낼 때 작용한다.
    // 소셜 로그인은 여기서 작동하지 않는다.
    public Authentication getAuthentication(String token) {
        // 토큰 복호화 메소드
        Claims claims = parseClaims(token);
        log.info("claims in JwtProvider  : " + claims);

        if(claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        Object auth = claims.get("auth");
        // [ROLE_USER]
        log.info("auth in JwtProvider : " + auth);

        // 클레임 권한 정보 가져오기
        List<String> authorityStrings = (List<String>) claims.get(AUTHORITIES_KEY);
        // [ROLE_USER]
        log.info("authorityStrings in JwtProvider : " + authorityStrings);

        Collection<? extends GrantedAuthority> authorities =
                authorityStrings.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // [ROLE_USER]
        log.info("authorities in JwtProvider : " + authorities);

        /*
            UserDetails를 사용하는 이유는 다음과 같습니다:
        *   1.  인증과 권한 정보 분리:
                Spring Security에서는 인증(Authentication)과 권한(Authorization)을 분리하는 것이 중요합니다.
                즉, 사용자의 인증 정보(아이디, 비밀번호 등)와 사용자의 권한 정보(역할, 권한)을 분리하여 관리하고 처리합니다.
                UserDetails는 사용자의 인증 정보를 담고 있으며, GrantedAuthority 객체들을 통해 사용자의 권한 정보를 나타낼 수 있습니다.

            2.  유연성:
                Spring Security는 다양한 인증 방식과 인증 제공자(Authentication Provider)를 지원합니다.
                UserDetails를 사용함으로써 각각의 인증 방식에 따라 사용자 정보를 일반화하여 처리할 수 있습니다.
                JWT 토큰을 사용하는 경우에도 UserDetails를 활용하면 일반적인 Spring Security의 흐름을 따르며,
                JWT 토큰에 포함된 사용자 정보와 권한을 UserDetails 객체로 추상화하여 처리할 수 있습니다.
        * */
        // Spring Security의 일반적인 원칙을 따르고, 인증 정보를 효율적이고 안전하게 관리하기 위한 방법 중 하나

        // PrincipalDetails 에 유저 정보가 있는데 밑의 작업을 하는 이유는 다음과 같다.
        // Spring Security의 내부 동작 및 일관성 유지를 위해 필요한 작업입니다.
        // PrincipalDetails 클래스는 UserDetails 인터페이스를 구현하여 사용자의 정보와 권한을 저장하는 역할을 하고 있습니다.
        // 그리고 UsernamePasswordAuthenticationToken은 Spring Security에서 인증을 나타내는 객체이며,
        // 인증된 사용자 정보와 해당 사용자의 권한 정보를 포함합니다.
        // JWT를 사용하여 인증을 처리할 때에는 토큰 검증 과정에서 사용자의 권한 정보를 추출하여
        // UsernamePasswordAuthenticationToken을 생성합니다.
        // 하지만 토큰 검증을 통해 가져온 권한 정보는 SimpleGrantedAuthority 객체의 리스트 형태로 제공됩니다.
        // 이 때, Spring Security가 기대하는 UserDetails 타입의 객체로 변환하여야 합니다.
        // 요약하면, 토큰 검증을 통해 가져온 권한 정보를 UserDetails 타입으로 변환하여
        // UsernamePasswordAuthenticationToken에 담아서 저장하는 것은 Spring Security의 일관성과 내부 동작을 따르는 방식입니다.
        UserDetails userDetails = new User(claims.getSubject(), "", authorities);
        log.info("claims.getSubject() in JwtProvider : " + claims.getSubject());
        log.info("userDetails.getUsername()  in JwtProvider : " + userDetails.getUsername());
        log.info("userDetails.getAuthorities() in JwtProvider : " + userDetails.getAuthorities());

        // 일반 로그인 시 주로 이거로 인증처리해서 SecurityContext에 저장한다.
        // Spring Security에서 인증을 나타내는 객체로 사용됩니다.
        // 일반적인 경우, 사용자 이름과 비밀번호를 사용하여 인증을 처리하고 해당 사용자의 권한 정보를 포함
        // 원래는 사용자 이름과 비밀번호를 사용하여 인증을 처리하고, 해당 사용자의 권한 정보를 포함합니다.
        // 일반적으로 이 객체를 사용하여 사용자가 입력한 인증 정보를 처리하고,
        // 인증이 성공하면 해당 사용자의 권한을 포함한 Authentication 객체가 생성되어 SecurityContext에 저장됩니다.
        // 그러나 JWT를 사용하는 경우에는 비밀번호 대신에 JWT 토큰을 사용하여 인증을 처리합니다.
        return new UsernamePasswordAuthenticationToken(userDetails, token, authorities);
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
