package com.example.study_project.controller;

import com.example.study_project.dto.ResponseDTO;
import com.example.study_project.dto.TodoDTO;
import com.example.study_project.entity.TodoEntity;
import com.example.study_project.service.TodoService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

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

    @PostMapping
    public ResponseEntity<?> createTodo(@RequestBody TodoDTO dto) {
        try {
            String temporaryUserId = "temporary-user";

            // (1) TodoEntity로 변환
            TodoEntity entity = TodoDTO.todoEntity(dto);

            // (2) id를 null로 초기화한다.
            // 생성 당시에는 id가 없어야 하기 때문이다.
            entity.setId(null);

            // (3) 임시 유저 아이디를 설정해준다.
            // 현재는 임시 아이디
            entity.setUserId(temporaryUserId);

            // (4) 서비스를 이용해 Todo엔티티를 생성한다.
            List<TodoEntity> entities = todoService.create(entity);

            // (5) 자바 스트림을 이용해 리턴된 엔티티 리스트를 TodoDTO 리스트로 변환한다.
            List<TodoDTO> dtos = entities.stream().map(TodoDTO::new).collect(Collectors.toList());

            // (6) 변환된 TodoDTO 리스트를 이용해 ResponseDTO를 초기화한다.
            ResponseDTO<TodoDTO> responseDTO = ResponseDTO.<TodoDTO>builder().data(dtos).build();

            // (7) ResponseDTO를 리턴한다.
            return ResponseEntity.ok().body(responseDTO);
        } catch (Exception e){
            // (8) 혹시 예외가 나는 경우 dto 대신 error에 메시지를 넣어 리턴한다.
            String error = e.getMessage();
            ResponseDTO<TodoDTO> responseDTO = ResponseDTO.<TodoDTO>builder().error(error).build();
            return ResponseEntity.badRequest().body(responseDTO);
        }
    }

    @GetMapping
    public ResponseEntity<?> retrieveTodoList() {
        String temporaryUserId = "temporary-user";

        // (1) 서비스 메서드의 retrieve 메서드를 사용해 Todo 리스트를 가져온다.
        List<TodoEntity> entities = todoService.retrieve(temporaryUserId);

        // (2) 자바 스트림을 이용해 리턴된 엔티티 리스트를 TodoDTO 리스트로 변환한다.
        List<TodoDTO> dtos = entities.stream().map(TodoDTO::new).collect(Collectors.toList());

        // (3) 변환된 TodoDTO 리스트를 이용해 ResponseDTO를 초기화한다.
        ResponseDTO<TodoDTO> responseDTO = ResponseDTO.<TodoDTO>builder().data(dtos).build();

        // (4) ResponseDTO를 리턴한다.
        return ResponseEntity.ok().body(responseDTO);
    }

    @PutMapping
    public ResponseEntity<?> updateTodo(@RequestBody TodoDTO todoDTO) {
        String temporaryUserId = "temporary-user";

        // (1) dto를 entity로 변환
        TodoEntity entity = TodoDTO.todoEntity(todoDTO);

        // (2) id를 temporaryUserId로 초기화한다.
        entity.setUserId(temporaryUserId);

        // (3) 서비스를 이용해 entity를 업데이트 한다.
        List<TodoEntity> entities = todoService.update(entity);

        // (4) 자바 스트림을 이용해 리턴된 엔티티 리스트를 TodoDTO 리스트로 변환한다.
        List<TodoDTO> dtos = entities.stream().map(TodoDTO::new).collect(Collectors.toList());

        // (5) 변횐된 TodoDTO 리스트를 이용해 ResponseDTO를 초기화한다.
        ResponseDTO<TodoDTO> responseDTO = ResponseDTO.<TodoDTO>builder().data(dtos).build();

        // (6) ResponseDTO를 리턴한다.
        return ResponseEntity.ok().body(responseDTO);
    }
}
