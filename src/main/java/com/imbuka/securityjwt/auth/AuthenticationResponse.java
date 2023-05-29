package com.imbuka.securityjwt.auth;

import lombok.*;

@Data
@AllArgsConstructor
@Builder
@NoArgsConstructor
public class AuthenticationResponse {

    private String token;
}
