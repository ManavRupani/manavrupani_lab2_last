package com.example.coffeshop_app.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.coffeshop_app.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);
}
