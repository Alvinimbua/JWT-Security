package com.imbuka.securityjwt.user;


import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.imbuka.securityjwt.user.Permissions.*;

@RequiredArgsConstructor
public enum Role {

    //each role can have multiple permissions

    USER(Collections.emptySet()),
    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_CREATE,
                    ADMIN_DELETE,
                    ADMIN_UPDATE,
                    MANAGER_DELETE,
                    MANAGER_CREATE,
                    MANAGER_UPDATE,
                    MANAGER_READ
            )
    ),
    MANAGER(
            Set.of(
                    MANAGER_DELETE,
                    MANAGER_CREATE,
                    MANAGER_UPDATE,
                    MANAGER_READ
            )
    );

    @Getter
    //using set to disallow duplications
    private final Set<Permissions> permissions;

    public List<SimpleGrantedAuthority> getAuthorities() {
        var authorities = getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
