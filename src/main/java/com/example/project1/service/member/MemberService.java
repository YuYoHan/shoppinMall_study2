package com.example.project1.service.member;

import com.example.project1.config.jwt.JwtProvider;
import com.example.project1.domain.jwt.TokenDTO;
import com.example.project1.domain.member.RequestMemberDTO;
import com.example.project1.entity.jwt.TokenEntity;
import com.example.project1.entity.member.MemberEntity;
import com.example.project1.repository.jwt.TokenRepository;
import com.example.project1.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@Transactional
@Log4j2
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final TokenRepository tokenRepository;
    private final ModelMapper modelMapper;
    
    public Long save(String email, String password) {
        MemberEntity makeEntity = MemberEntity.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .build();
        MemberEntity saveMember = memberRepository.save(makeEntity);
        log.info(saveMember);
        return saveMember.getId();
    }

    public TokenDTO login(String email, String password) {
        boolean isUser = memberRepository.existsByEmail(email);
        MemberEntity memberEntity;
        TokenEntity findToken;
        TokenDTO tokenDTO = null;

        if(isUser) {
            memberEntity = memberRepository.findByEmail(email);
            if(passwordEncoder.matches(password, memberRepository.findByEmail(email).getPassword())) {

                List<GrantedAuthority> authoritiesForUser = getAuthoritiesForUser(memberEntity);
                tokenDTO= jwtProvider.createToken(email, authoritiesForUser);
                findToken = tokenRepository.findByEmail(email);
                boolean isToken = tokenRepository.existsByEmail(email);
                if(!isToken) {
                    TokenEntity changeTokenEntity = modelMapper.map(tokenDTO, TokenEntity.class);
                    findToken = tokenRepository.save(changeTokenEntity);
                } else {
                    findToken.update(tokenDTO);
                }
                tokenRepository.save(findToken);
            }
        }
        return tokenDTO;


    }
    private List<GrantedAuthority> getAuthoritiesForUser(MemberEntity member) {
        String role = member.getRole();
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        log.info("role : " + authorities);
        return authorities;
    }

}
