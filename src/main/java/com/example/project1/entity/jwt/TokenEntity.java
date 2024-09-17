package com.example.project1.entity.jwt;

import com.example.project1.domain.jwt.TokenDTO;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class TokenEntity {
    @Id @GeneratedValue
    private Long id;
    private String grantType;
    private String accessToken;
    private String refreshToken;
    private String email;

    public void update(TokenDTO token) {
        this.accessToken = token.getAccessToken();
        this.refreshToken = token.getRefreshToken();
    }
}
