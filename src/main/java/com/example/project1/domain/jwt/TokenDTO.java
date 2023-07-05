package com.example.project1.domain.jwt;

import com.example.project1.entity.jwt.TokenEntity;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@NoArgsConstructor
public class TokenDTO {
    // JWT 대한 인증 타입, 여기서는 Bearer를 사용하고
    // 이후 HTTP 헤더에 prefix로 붙여주는 타입
    private String grantType;
    private String accessToken;
    private String refreshToken;
    private String userEmail;
    private String nickName;

    @Builder
    public TokenDTO(String grantType, String accessToken, String refreshToken, String userEmail, String nickName) {
        this.grantType = grantType;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.userEmail = userEmail;
        this.nickName = nickName;
    }

    public static TokenDTO toTokenDTO(TokenEntity tokenEntity) {
        TokenDTO tokenDTO = TokenDTO.builder()
                .grantType(tokenEntity.getGrantType())
                .accessToken(tokenEntity.getAccessToken())
                .refreshToken(tokenEntity.getRefreshToken())
                .userEmail(tokenEntity.getUserEmail())
                .nickName(tokenEntity.getNickName())
                .build();

        return tokenDTO;
    }
}
