package com.example.project1.service.jwt;

import com.example.project1.config.jwt.JwtAuthenticationFilter;
import com.example.project1.config.jwt.JwtProvider;
import com.example.project1.domain.jwt.TokenDTO;
import com.example.project1.domain.member.UserType;
import com.example.project1.entity.jwt.TokenEntity;
import com.example.project1.entity.member.MemberEntity;
import com.example.project1.repository.jwt.TokenRepository;
import com.example.project1.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final TokenRepository tokenRepository;
    private final JwtProvider jwtProvider;
    private final MemberRepository memberRepository;

    public ResponseEntity<TokenDTO> createAccessToken(String refreshToken) {

        if(jwtProvider.validateRefreshToken(refreshToken)) {
            // 아이디 추출
            String userEmail = jwtProvider.extractUserEmailFromToken(refreshToken);
            log.info("userEmail : " + userEmail);
            MemberEntity member = memberRepository.findByUserEmail(userEmail);
            log.info("member : " + member);
            // 사용자의 권한 정보를 가져옴
            List<GrantedAuthority> authoritiesForUser = getAuthoritiesForUser(member);

            TokenDTO accessToken = jwtProvider.createAccessToken(userEmail, authoritiesForUser);
            log.info("accessToken : " + accessToken);

            HttpHeaders headers = new HttpHeaders();
            // response header에 jwt token을 넣어줌
            headers.add(JwtAuthenticationFilter.HEADER_AUTHORIZATION, "Bearer " + accessToken);
            TokenEntity tokenEntity = TokenEntity.builder()
                    .grantType(accessToken.getGrantType())
                    .accessToken(accessToken.getAccessToken())
                    .userEmail(userEmail)
                    .nickName(member.getNickName())
                    .userId(member.getUserId())
                    .build();

            log.info("token : " + tokenEntity);
            tokenRepository.save(tokenEntity);
            TokenDTO token2 = TokenDTO.toTokenDTO(tokenEntity);

            return new ResponseEntity<>(token2, headers, HttpStatus.OK);
        } else {
            throw new IllegalArgumentException("Unexpected token");
                }
            }

    // 주어진 사용자에 대한 권한 정보를 가져오는 로직을 구현하는 메서드입니다.
    // 이 메서드는 데이터베이스나 다른 저장소에서 사용자의 권한 정보를 조회하고,
    // 해당 권한 정보를 List<GrantedAuthority> 형태로 반환합니다.
    private List<GrantedAuthority> getAuthoritiesForUser(MemberEntity member) {
        // 예시: 데이터베이스에서 사용자의 권한 정보를 조회하는 로직을 구현
        // member 객체를 이용하여 데이터베이스에서 사용자의 권한 정보를 조회하는 예시로 대체합니다.
        UserType role = member.getUserType();  // 사용자의 권한 정보를 가져오는 로직 (예시)

        List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(role.name()));
        return authorities;
    }
}
