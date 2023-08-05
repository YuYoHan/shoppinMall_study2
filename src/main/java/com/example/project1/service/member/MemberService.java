package com.example.project1.service.member;

import com.example.project1.config.auth.PrincipalDetails;
import com.example.project1.config.jwt.JwtAuthenticationFilter;
import com.example.project1.config.jwt.JwtProvider;
import com.example.project1.domain.jwt.TokenDTO;
import com.example.project1.domain.member.MemberDTO;
import com.example.project1.domain.member.UserType;
import com.example.project1.domain.member.embedded.AddressDTO;
import com.example.project1.entity.jwt.TokenEntity;
import com.example.project1.entity.member.MemberEntity;
import com.example.project1.entity.member.embedded.AddressEntity;
import com.example.project1.repository.jwt.TokenRepository;
import com.example.project1.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final TokenRepository tokenRepository;

    // 회원가입
    public String signUp(MemberDTO memberDTO) throws Exception {

        try {
            MemberEntity byUserEmail = memberRepository.findByUserEmail(memberDTO.getUserEmail());

            if (byUserEmail != null) {
                return "이미 가입된 회원입니다.";
            } else {
                // 아이디가 없다면 DB에 넣어서 등록 해준다.
                MemberEntity member = MemberEntity.builder()
                        .userEmail(memberDTO.getUserEmail())
                        .userPw(passwordEncoder.encode(memberDTO.getUserPw()))
                        .userName(memberDTO.getUserName())
                        .nickName(memberDTO.getNickName())
                        .userType(memberDTO.getUserType())
                        .provider(memberDTO.getProvider())
                        .providerId(memberDTO.getProviderId())
                        .address(AddressEntity.builder()
                                .userAddr(memberDTO.getAddressDTO().getUserAddr())
                                .userAddrDetail(memberDTO.getAddressDTO().getUserAddrDetail())
                                .userAddrEtc(memberDTO.getAddressDTO().getUserAddrEtc())
                                .build())
                        .build();

                log.info("member : " + member);
                memberRepository.save(member);

//            MemberDTO memberDTO1 = MemberDTO.toMemberDTO(Optional.of(save));

                return "회원가입에 성공했습니다.";
            }

        } catch (Exception e) {
            log.error(e.getMessage());
            throw e; // 예외를 던져서 예외 처리를 컨트롤러로 전달
        }

    }

    // 아이디 조회
    public MemberDTO search(Long userId) {
        Optional<MemberEntity> searchId = memberRepository.findById(userId);
        MemberDTO memberDTO = MemberDTO.toMemberDTO(searchId);
        return memberDTO;
    }

    // 회원 삭제
    public String remove(Long userId) {
        MemberEntity member = memberRepository.deleteByUserId(userId);

        if (member == null) {
            return "회원 탈퇴 완료!";
        } else {
            return "회원 탈퇴 실패!";
        }
    }

    // 로그인
    public ResponseEntity<TokenDTO> login(String userEmail, String userPw) throws Exception {

        MemberEntity findUser = memberRepository.findByUserEmail(userEmail);
        log.info("findUser : " + findUser);


        if (findUser != null) {
            // 사용자가 입력한 패스워드를 암호화하여 사용자 정보와 비교
            if (passwordEncoder.matches(userPw, findUser.getUserPw())) {
                // UsernamePasswordAuthenticationToken은 Spring Security에서
                // 사용자의 이메일과 비밀번호를 이용하여 인증을 진행하기 위해 제공되는 클래스
                // 이후에는 생성된 authentication 객체를 AuthenticationManager를 이용하여 인증을 진행합니다.
                // AuthenticationManager는 인증을 담당하는 Spring Security의 중요한 인터페이스로, 실제로 사용자의 인증 과정을 처리합니다.
                // AuthenticationManager를 사용하여 사용자가 입력한 이메일과 비밀번호가 올바른지 검증하고,
                // 인증에 성공하면 해당 사용자에 대한 Authentication 객체를 반환합니다. 인증에 실패하면 예외를 발생시킵니다.
                // 인증은 토큰을 서버로 전달하고, 서버에서 해당 토큰을 검증하여 사용자를 인증하는 단계에서 이루어집니다.
                Authentication authentication = new UsernamePasswordAuthenticationToken(userEmail, userPw);

                //  UsernamePasswordAuthenticationToken
                //  [Principal=zxzz45@naver.com, Credentials=[PROTECTED], Authenticated=false, Details=null, Granted Authorities=[]]
                // 여기서 Authenticated=false는 아직 정상임
                // 이 시점에서는 아직 실제로 인증이 이루어지지 않았기 때문에 Authenticated 속성은 false로 설정
                // 인증 과정은 AuthenticationManager와 AuthenticationProvider에서 이루어지며,
                // 인증이 성공하면 Authentication 객체의 isAuthenticated() 속성이 true로 변경됩니다.
                log.info("authentication in MemberService : " + authentication);

                List<GrantedAuthority> authoritiesForUser = getAuthoritiesForUser(findUser);

//                TokenDTO token = jwtProvider.createToken(authentication, findUser.getUserType());
                TokenDTO token = jwtProvider.createToken(authentication, authoritiesForUser);

                log.info("tokenEmail in MemberService : " + token.getUserEmail());

                TokenEntity checkEmail = tokenRepository.findByUserEmail(token.getUserEmail());
                log.info("checkEmail in MemberService : " + checkEmail);

                // 사용자에게 이미 토큰이 할당되어 있는지 확인합니다.
                if (checkEmail != null) {
                    log.info("이미 발급한 토큰이 있습니다.");
                    // 발급한 토큰이 있을 때 id를 식별해서 수정한다.
                    // id가 없으면 새로운 거로 인식해서 새로 저장된다.
                    token = TokenDTO.builder()
                            .id(checkEmail.getId())
                            .grantType(token.getGrantType())
                            .accessToken(token.getAccessToken())
                            .refreshToken(token.getRefreshToken())
                            .userEmail(token.getUserEmail())
                            .nickName(findUser.getNickName())
                            .userId(findUser.getUserId())
                            .accessTokenTime(token.getAccessTokenTime())
                            .refreshTokenTime(token.getRefreshTokenTime())
                            .userType(findUser.getUserType())
                            .build();

                    TokenEntity updateToken = TokenEntity.toTokenEntity(token);


                    log.info("token in MemberService : " + updateToken);
                    tokenRepository.save(updateToken);
                } else {
                    log.info("발급한 토큰이 없습니다.");
                    token = TokenDTO.builder()
                            .grantType(token.getGrantType())
                            .accessToken(token.getAccessToken())
                            .refreshToken(token.getRefreshToken())
                            .userEmail(token.getUserEmail())
                            .nickName(findUser.getNickName())
                            .userId(findUser.getUserId())
                            .accessTokenTime(token.getAccessTokenTime())
                            .refreshTokenTime(token.getRefreshTokenTime())
                            .userType(findUser.getUserType())
                            .build();


                    // 새로운 토큰을 DB에 저장할 때 사용할 임시 객체로 TokenEntity tokenEntity를 생성합니다.
                    TokenEntity newToken = TokenEntity.toTokenEntity(token);

                    log.info("token in MemberService : " + newToken);
                    tokenRepository.save(newToken);
                }
                HttpHeaders headers = new HttpHeaders();
                // response header에 jwt token을 넣어줌
                headers.add(JwtAuthenticationFilter.HEADER_AUTHORIZATION, "Bearer " + token);

                return new ResponseEntity<>(token, headers, HttpStatus.OK);
            }
        } else {
            return null;
        }
        return null;
    }

    private List<GrantedAuthority> getAuthoritiesForUser(MemberEntity member) {
        // 예시: 데이터베이스에서 사용자의 권한 정보를 조회하는 로직을 구현
        // member 객체를 이용하여 데이터베이스에서 사용자의 권한 정보를 조회하는 예시로 대체합니다.
        UserType role = member.getUserType();  // 사용자의 권한 정보를 가져오는 로직 (예시)

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.name()));
        log.info("role in MemberService : " + role.name());
        log.info("authorities in MemberService : " + authorities);
        return authorities;
    }


    // 회원정보 수정
    public MemberDTO update(MemberDTO memberDTO) {

        MemberEntity findUser = memberRepository.findByUserEmail(memberDTO.getUserEmail());

        // 새로 가입
        if (findUser == null) {
            findUser = MemberEntity.builder()
                    .userEmail(memberDTO.getUserEmail())
                    .userPw(passwordEncoder.encode(memberDTO.getUserPw()))
                    .userType(memberDTO.getUserType())
                    .userName(memberDTO.getUserName())
                    .nickName(memberDTO.getNickName())
                    .address(AddressEntity.builder()
                            .userAddr(memberDTO.getAddressDTO().getUserAddr())
                            .userAddrDetail(memberDTO.getAddressDTO().getUserAddrDetail())
                            .userAddrEtc(memberDTO.getAddressDTO().getUserAddrEtc())
                            .build()).build();

            memberRepository.save(findUser);
            MemberDTO modifyUser = MemberDTO.toMemberDTO(Optional.of(findUser));
            return modifyUser;
        } else {
            // 회원 수정
            findUser = MemberEntity.builder()
                    // id를 식별해서 수정
                    // 이거 없으면 새로 저장하기 됨
                    // findUser꺼를 쓰면 db에 입력된거를 사용하기 때문에
                    // 클라이언트에서 userEmail을 전달하더라도 서버에서 기존 값으로 업데이트가 이루어질 것입니다.
                    // 이렇게 하면 userEmail을 수정하지 못하게 할 수 있습니다.
                    .userId(findUser.getUserId())
                    .userEmail(findUser.getUserEmail())
                    .userPw(passwordEncoder.encode(memberDTO.getUserPw()))
                    .userName(memberDTO.getUserName())
                    .nickName(memberDTO.getNickName())
                    .userType(memberDTO.getUserType())
                    .address(AddressEntity.builder()
                            .userAddr(memberDTO.getAddressDTO().getUserAddr())
                            .userAddrDetail(memberDTO.getAddressDTO().getUserAddrDetail())
                            .userAddrEtc(memberDTO.getAddressDTO().getUserAddrEtc())
                            .build())
                    .build();

            memberRepository.save(findUser);
            // 제대로 DTO 값이 엔티티에 넣어졌는지 확인하기 위해서
            // 엔티티에 넣어주고 다시 DTO 객체로 바꿔서 리턴을 해줬습니다.
            MemberDTO memberDto = MemberDTO.toMemberDTO(Optional.of(findUser));
            log.info("memberDto : " + memberDto);
            return memberDto;
        }
    }

    // 소셜 로그인 성공시 jwt 반환
    // OAuth2User에서 필요한 정보를 추출하여 UserDetails 객체를 생성하는 메서드
    public ResponseEntity<TokenDTO> createToken(MemberDTO memberDTO) {

        String email = memberDTO.getUserEmail();
        String nickName = memberDTO.getNickName();

        MemberEntity findEmail = memberRepository.findByUserEmail(email);
        log.info("findEmail in MemberService : " + findEmail);

        // 기존의 멤버 엔티티 수정
        findEmail = MemberEntity.builder()
                .userId(findEmail.getUserId())
                .nickName(nickName)
                .address(AddressEntity.builder()
                        .userAddr(memberDTO.getAddressDTO().getUserAddr())
                        .userAddrEtc(memberDTO.getAddressDTO().getUserAddrEtc())
                        .userAddrDetail(memberDTO.getAddressDTO().getUserAddrDetail())
                        .build())
                .build();

        memberRepository.save(findEmail);

        if(!(findEmail.getProvider().isEmpty()) && !(findEmail.getProviderId().isEmpty())) {
            TokenEntity findToken = tokenRepository.findByUserEmail(findEmail.getUserEmail());
            log.info("findToken in MemberService : " + findToken);
            if (findToken != null) {
                TokenDTO tokenDTO = TokenDTO.builder()
                        .id(findToken.getId())
                        .grantType(findToken.getGrantType())
                        .accessToken(findToken.getAccessToken())
                        .accessTokenTime(findToken.getAccessTokenTime())
                        .refreshToken(findToken.getRefreshToken())
                        .refreshTokenTime(findToken.getRefreshTokenTime())
                        .userEmail(findToken.getUserEmail())
                        .nickName(nickName)
                        .build();

                return ResponseEntity.ok().body(tokenDTO);
        } else {
                return null;
            }
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}
