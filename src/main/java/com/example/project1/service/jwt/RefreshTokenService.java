package com.example.project1.service.jwt;

import com.example.project1.config.jwt.JwtAuthenticationFilter;
import com.example.project1.config.jwt.JwtProvider;
import com.example.project1.domain.jwt.TokenDTO;
import com.example.project1.entity.jwt.TokenEntity;
import com.example.project1.entity.member.MemberEntity;
import com.example.project1.repository.jwt.TokenRepository;
import com.example.project1.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final TokenRepository tokenRepository;
    private final JwtProvider jwtProvider;
    private final MemberRepository memberRepository;

    public ResponseEntity<TokenDTO> createAccessToken(String token) {
        // 헤더에서 리프레시 토큰 추출
        String refreshToken = null;

        if (token != null && token.startsWith("Bearer ")) {
            // "Bearer " 제외한 토큰 추출
            refreshToken = token.substring(7);

            // refreshToken 이 토큰 레포지토리에 있는지 확인하고 byRefreshToken 에 담아준다.
            TokenEntity byRefreshToken = tokenRepository.findByRefreshToken(refreshToken);
            // byRefreshToken 에서 리프레쉬 토큰이 null 이 아니거나 byRefreshToken 의 리프레쉬토큰과
            // header 에서 받아온 refreshToken 이 같다면 true 입니다.
            if (byRefreshToken.getRefreshToken() != null && byRefreshToken.getRefreshToken().equals(refreshToken)) {
                // 리프레시 토큰을 유효성 검사를 해주고 validateRefreshToken 담아준다.
                boolean validateRefreshToken = jwtProvider.validateToken(String.valueOf(byRefreshToken.getRefreshToken()));


                if (validateRefreshToken) {
                    // 위에서 찾아온 byRefreshToken 에서 userEmail 을 담아준다.
                    String userEmail = byRefreshToken.getUserEmail();
                    // access token 생성
                    TokenDTO accessToken = jwtProvider.createAccessToken(userEmail);

                    HttpHeaders headers = new HttpHeaders();

                    // response header에 jwt token을 넣어줌
                    headers.add(JwtAuthenticationFilter.HEADER_AUTHORIZATION, "Bearer " + accessToken);

                    MemberEntity member = memberRepository.findByUserEmail(userEmail);
                    log.info("member : " + member);

                    TokenEntity tokenEntity = TokenEntity.builder()
                            .grantType(accessToken.getGrantType())
                            .accessToken(accessToken.getAccessToken())
                            .refreshToken(byRefreshToken.getRefreshToken())
                            .userEmail(userEmail)
                            .nickName(member.getNickName())
                            .userId(member.getUserId())
                            .build();

                    log.info("token : " + tokenEntity);

                    tokenRepository.save(tokenEntity);
                    TokenDTO token2 = TokenDTO.toTokenDTO(tokenEntity);

                    return new ResponseEntity<>(token2, headers, HttpStatus.OK);
                }
            } else {
                throw new IllegalArgumentException("Unexpected token");
            }
        }
        return ResponseEntity.notFound().build();
    }
}
