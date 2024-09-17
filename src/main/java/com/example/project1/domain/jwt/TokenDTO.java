package com.example.project1.domain.jwt;

import lombok.*;

@Getter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenDTO {
    private String grantType;
    private String accessToken;
    private String refreshToken;
    private String email;
}
