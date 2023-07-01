package com.example.project1.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;

@Entity
@Getter
@ToString
@NoArgsConstructor
public class MemberEntity extends BaseEntity{
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "user_name", nullable = false)
    private  String userName;

    @Column(name = "user_email", nullable = false)
    private String userEmail;

    @Column(name = "user_pw")
    private String userPw;

    // ROLE_USER, ROLE_ADMIN
    private String role;

    // OAuth2 가입할 때를 위해서
    private String provider;
    private String providerId;
}
