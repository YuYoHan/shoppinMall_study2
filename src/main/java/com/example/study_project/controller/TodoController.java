package com.example.study_project.controller;

import com.example.study_project.dto.ResponseDTO;
import com.example.study_project.service.TodoService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/todo")
@RequiredArgsConstructor
public class TodoController {

    private final TodoService todoService;

    @GetMapping("/test")
    public ResponseEntity<?> testTodo() {
        String str = todoService.testService(); // 테스트 서비스 사용
        List<String> list = new ArrayList<>();
        list.add(str);

        ResponseDTO<String> responseDTO = ResponseDTO.<String>builder()
                .data(list)
                .build();

        return ResponseEntity.ok().body(responseDTO);
    }
}
