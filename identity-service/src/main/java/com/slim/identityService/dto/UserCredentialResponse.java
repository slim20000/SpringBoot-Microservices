package com.slim.identityService.dto;

import com.slim.identityService.model.UserCredential;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UserCredentialResponse {
    private String token;
    private UserCredential user;
}
