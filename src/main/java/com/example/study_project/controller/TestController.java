package com.example.study_project.controller;


import com.example.study_project.dto.RequestBodyDTO;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class TestController {
    @GetMapping()
    public String test() {
        return "Hello World";
    }

    @GetMapping("/{id}")
    public String testPathVariable(@PathVariable(required = false) int id) {
        return "Hello World! Id " + id;
    }

    // ...:8080/test/testRequestParam?id=123 이런식
    @GetMapping("/testRequestParam")
    public String testRequestParam(@RequestParam(required = false) int id) {
        return "Hello World! Id " + id;
    }

    // RequestBody로 날라오는 JSON을 RequestBodyDTO 오브젝트로 변환해 가져오는 것
    // 클라이언트 : JSON → 서버 : JSON ▶ DTO
    @GetMapping("/testRequestBody")
    public String testRequestBody(@RequestBody RequestBodyDTO requestBodyDTO) {
        return "Hello ID " + requestBodyDTO.getId() + " Message : " + requestBodyDTO.getMessage();
    }
}
