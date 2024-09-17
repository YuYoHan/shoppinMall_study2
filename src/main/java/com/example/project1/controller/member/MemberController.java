package com.example.project1.controller.member;

import com.example.project1.domain.jwt.TokenDTO;
import com.example.project1.domain.member.RequestMemberDTO;
import com.example.project1.service.member.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Log4j2
@RequestMapping("/api")
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/join")
    public ResponseEntity<?> join(@RequestBody @Validated RequestMemberDTO member) {
        String email = member.getEmail();
        String password = member.getPassword();

        Long responseId = memberService.save(email, password);

        return ResponseEntity.ok(responseId);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Validated RequestMemberDTO member) {
        String email = member.getEmail();
        String password = member.getPassword();
        TokenDTO login = memberService.login(email, password);
        return ResponseEntity.ok(login);
    }
}
