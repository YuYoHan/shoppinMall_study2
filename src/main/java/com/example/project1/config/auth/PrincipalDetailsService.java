package com.example.project1.config.auth;

import com.example.project1.entity.member.MemberEntity;
import com.example.project1.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login ← 이 때 동작을 함

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private MemberRepository memberRepository;

    // 시큐리티 session = Authentication = UserDetails
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {
        MemberEntity member = memberRepository.findByUserEmail(userEmail);
        log.info("user in PrincipalDetailsService : " + member);
        return new PrincipalDetails(member);
    }


}
