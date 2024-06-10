package com.jwt.spring_security.dto.request;


import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {

    private String email;

    private String password;
}
