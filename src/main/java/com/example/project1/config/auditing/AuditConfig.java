package com.example.project1.config.auditing;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
// JPA의 Auditing 기능을 활성화
@EnableJpaAuditing
public class AuditConfig {
    // 등록자와 수정자를 처리해주는 AuditorAware을 빈으로 등록합니다.
    @Bean
    public AuditorAware<String> auditorProvider() {
        return new AuditorAwareImpl();
    }
}
