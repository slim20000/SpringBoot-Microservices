package com.slim.identityService.repository;

import com.slim.identityService.model.UserCredential;
import com.slim.identityService.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserCredentialRepository extends JpaRepository<UserCredential, Integer> {

    Optional<UserCredential> findByUsername(String username);

    Optional<UserCredential> findByEmail(String email);

    Optional<UserCredential> findByVerificationCode(String verificationCode);

    List<UserCredential> findByRole(UserRole role);
}
