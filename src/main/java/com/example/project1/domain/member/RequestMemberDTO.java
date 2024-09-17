package com.example.project1.domain.member;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import org.springframework.web.bind.annotation.GetMapping;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Getter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RequestMemberDTO {
    @NotNull(message = "이메일은 필 수 입니다.")
    @Pattern(regexp = "^(?:\\w+\\.?)*\\w+@(?:\\w+\\.)+\\w+$",
    message = "이메일 형식이 바르지 않습니다.")
    @Email(message = "이메일 형식에 맞지 않습니다.")
    private String email;
    private String password;
}
