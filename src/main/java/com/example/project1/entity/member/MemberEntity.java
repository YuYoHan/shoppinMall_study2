package com.example.project1.entity.member;

import lombok.*;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Getter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MemberEntity {
    @Id @GeneratedValue
    private Long id;
    private String email;
    private String password;
    private String role;
}
