package com.example.project1.controller.member;

import com.example.project1.domain.jwt.TokenDTO;
import com.example.project1.domain.member.MemberDTO;
import com.example.project1.service.member.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api/v1/users/**")
public class MemberController {

    private final MemberService memberService;

    // 회원 가입
    @PostMapping("/")
    // BindingResult 타입의 매개변수를 지정하면 BindingResult 매개 변수가 입력값 검증 예외를 처리한다.
    public ResponseEntity<?> join(@Validated @RequestBody MemberDTO memberDTO,
                                  BindingResult result) throws Exception{

        // 입력값 검증 예외가 발생하면 예외 메시지를 응답한다.
        if(result.hasErrors()) {
            log.info("BindingResult error : " + result.hasErrors());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(result.getClass().getSimpleName());
        }

        try {
            String join = memberService.signUp(memberDTO);
            // 아이디가 있으면 아이디가 존재합니다 리턴
            // 아이디가 없으면 회원가입에 성공했습니다가 리턴
            return ResponseEntity.ok().body(join);
        } catch (Exception e) {
            log.error("예외 : " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    // 회원 조회
    @GetMapping("/{userId}")
    public ResponseEntity<MemberDTO> search(@PathVariable Long userId) throws Exception {
        try {
            MemberDTO search = memberService.search(userId);
            return ResponseEntity.ok().body(search);
        } catch (NullPointerException e) {
            log.info("회원이 존재하지 않습니다.");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }

    // 로그인
    @PostMapping("/login")
    public ResponseEntity<TokenDTO> login(@RequestBody MemberDTO memberDTO) throws Exception {
        try {
            return memberService.login(memberDTO.getUserEmail(), memberDTO.getUserPw());
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    // 로그아웃
    @GetMapping("/logOut")
    public String logOut(HttpServletRequest request,
                         HttpServletResponse response) {
        new SecurityContextLogoutHandler().logout(request,
                response,
                SecurityContextHolder.getContext().getAuthentication());
        return "로그아웃하셨습니다.";
    }

    // 회원정보 수정
    @PutMapping("/")
    public ResponseEntity<?> update(@RequestBody MemberDTO memberDTO) throws Exception{
        try {
            MemberDTO update = memberService.update(memberDTO);
            return ResponseEntity.ok().body(update);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("잘못된 요청");
        }
    }
}
