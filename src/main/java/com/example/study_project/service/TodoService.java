package com.example.study_project.service;

import com.example.study_project.entity.TodoEntity;
import com.example.study_project.repository.TodoRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class TodoService {

    @Autowired
    private TodoRepository todoRepository;

    public String testService() {
        // TodoEntity 생성
        TodoEntity todoEntity = TodoEntity.builder()
                .title("My first todo item").build();

        // TodoEntity 저장
        todoRepository.save(todoEntity);

        // TodoEntity 검색
        TodoEntity savedEntity = todoRepository.findById(todoEntity.getId()).get();
        return savedEntity.getTitle();
    }

    public List<TodoEntity> create(final TodoEntity entity){
        // Validations
        if(entity == null) {
            log.warn("Entity cannot be null");
            throw new RuntimeException("Entity cannot be null");
        }

        if(entity.getUserId() == null) {
            log.warn("Unknown user");
            throw new RuntimeException("Unknown user");
        }

        todoRepository.save(entity);

        log.info("Entity Id : {} is saved.", entity.getId());
        return todoRepository.findByUserId(entity.getUserId());

    }

    public List<TodoEntity> retrieve(final String userId){
        return todoRepository.findByUserId(userId);
    }
}
