package com.example.project1.repository.jwt;

import com.example.project1.entity.jwt.TokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenRepository extends JpaRepository<TokenEntity, Long> {
    TokenEntity findByEmail(String email);
    boolean existsByEmail(String email);
}
