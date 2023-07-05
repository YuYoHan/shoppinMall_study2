package com.example.project1.repository.member;

import com.example.project1.entity.member.MemberEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MemberRepository extends JpaRepository<MemberEntity, Long> {
    // findBy규칙 → Username 문법
    // select * from user where username = 1?
    MemberEntity findByUserEmail(String userEmail);
}
