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
    private Long id;
    // JWT 대한 인증 타입, 여기서는 Bearer를 사용하고
    // 이후 HTTP 헤더에 prefix로 붙여주는 타입
    private String grantType;
    private String accessToken;
    private String refreshToken;
    private String userEmail;
    private String nickName;
    private Long userId;

    @Builder
    public TokenDTO(String grantType, String accessToken, String refreshToken, String userEmail, String nickName, Long userId) {
        this.grantType = grantType;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.userEmail = userEmail;
        this.nickName = nickName;
        this.userId = userId;
    }

    public static TokenDTO toTokenDTO(TokenEntity tokenEntity) {
        TokenDTO tokenDTO = TokenDTO.builder()
                .grantType(tokenEntity.getGrantType())
                .accessToken(tokenEntity.getAccessToken())
                .refreshToken(tokenEntity.getRefreshToken())
                .userEmail(tokenEntity.getUserEmail())
                .nickName(tokenEntity.getNickName())
                .userId(tokenEntity.getId())
                .build();

        return tokenDTO;
    }
}
