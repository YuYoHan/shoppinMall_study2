package com.example.project1.repository.member;

import com.example.project1.entity.member.MemberEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<MemberEntity, Long> {
    MemberEntity findByEmail(String email);
    boolean existsByEmail(String email);
}
