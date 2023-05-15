package com.example.study_project.service;

import com.example.study_project.entity.TodoEntity;
import com.example.study_project.repository.TodoRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class TodoService {

    @Autowired
    private TodoRepository todoRepository;

    private void validate(final TodoEntity entity) {
        if(entity == null) {
            log.warn("Entity cannot be null");
            throw new RuntimeException("Entity cannot be null");
        }
        if(entity.getUserId() == null) {
            log.warn("Unknown User");
            throw new RuntimeException("Unknown User");
        }
    }

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

    public List<TodoEntity> update(final TodoEntity entity) {
        // 저장할 엔티티가 유효한지 확인한다.
        validate(entity);

        // (2) 넘겨받은 엔티티 id를 이용해 TodoEntity를 가져온다.
        // 존재하지 않는 엔티티는 업데이트할 수 없기 때문이다.
        final Optional<TodoEntity> original = todoRepository.findById(entity.getId());

        original.ifPresent(todo -> {
            // (3) 반환된 TodoEntity가 존재하면 값을 새 entity의 값으로 덮어 씌운다.
            todo.setTitle(entity.getTitle());
            todo.setDone(entity.isDone());

            // (4) 데이터베이스에 새 값을 저장한다.
            todoRepository.save(todo);
        });
        // retrieve 메서드를 이용해서 유저의 모든 Todo 리스트를 리턴한다.
        return retrieve(entity.getUserId());
    }

    public List<TodoEntity> delete(final TodoEntity entity) {
        // 저장할 엔티티가 유효한지 확인한다.
        validate(entity);

        try {
            // (1) 엔티티를 삭제한다.
            todoRepository.delete(entity);
        } catch (Exception e) {
            // (2) exception 발생 시 id와 exception을 로깅한다.
            log.error("error deleting entity", entity.getId(), e);

            // (4) 컨트롤러로 exception을 날린다.
            // 데이터베이스 내부 로직을 캡슐화하기 위해 e를 리턴하지 않고
            // 새 exception 오브젝트를 리턴한다.
            throw new RuntimeException("error deleting entity" + entity.getId());
        }
        // (5) 새 Todo 리스트를 가져와 리턴한다.
        return retrieve(entity.getUserId());
    }
}
