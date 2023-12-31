package com.app.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.app.model.Task;

public interface TaskRepository extends JpaRepository<Task, Long> {
}
