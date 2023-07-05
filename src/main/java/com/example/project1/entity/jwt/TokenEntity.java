package com.example.project1.entity.jwt;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
@Getter
@NoArgsConstructor
@ToString
public class TokenEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String grantType;
    private String accessToken;
    private String refreshToken;
    private String userEmail;
    private String nickName;


    @Builder
    public TokenEntity(String grantType, String accessToken, String refreshToken, String userEmail, String nickName) {
        this.grantType = grantType;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.userEmail = userEmail;
        this.nickName = nickName;
    }
}
