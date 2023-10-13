package com.slim.candidat.client;

import lombok.*;


@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UserResponse {
    private int id;
    private String username;
    private String email;

}
