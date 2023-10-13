package com.slim.candidat.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "identity-service" , url = "http://localhost:7272")
public interface IdentityServiceClient {

    @GetMapping("auth/getById/{id}")
    ResponseEntity<UserResponse> getUserById(
            @PathVariable Integer id);
 }

