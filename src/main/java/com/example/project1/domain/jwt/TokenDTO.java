package com.example.project1.domain.jwt;

import com.example.project1.domain.member.UserType;
import com.example.project1.entity.jwt.TokenEntity;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import net.minidev.json.annotate.JsonIgnore;

import java.util.Date;

@Getter
@ToString
@NoArgsConstructor
public class TokenDTO {
    @JsonIgnore
    private Long id;
    // JWT 대한 인증 타입, 여기서는 Bearer를 사용하고
    // 이후 HTTP 헤더에 prefix로 붙여주는 타입
    private String grantType;
    private String accessToken;
    private String refreshToken;
    private String userEmail;
    private String nickName;
    private Long userId;
    private Date accessTokenTime;
    private Date refreshTokenTime;
    private UserType userType;

    @Builder
    public TokenDTO(
            Long id,
            String grantType,
            String accessToken,
            String refreshToken,
            String userEmail,
            String nickName,
            Long userId,
            Date accessTokenTime,
            Date refreshTokenTime,
            UserType userType
    ) {
        this.id = id;
        this.grantType = grantType;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.userEmail = userEmail;
        this.nickName = nickName;
        this.userId = userId;
        this.accessTokenTime = accessTokenTime;
        this.refreshTokenTime = refreshTokenTime;
        this.userType = userType;
    }

}
