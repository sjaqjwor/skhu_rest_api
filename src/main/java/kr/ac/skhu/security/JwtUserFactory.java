package kr.ac.skhu.security;

import java.util.List;
import java.util.stream.Collectors;

import kr.ac.skhu.model.security.Authority;
import kr.ac.skhu.model.security.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public final class JwtUserFactory {

    private JwtUserFactory() {
    }

    public static JwtUser create(User user) {
        return new JwtUser(
                user.getLoginId(),
                user.getName(),
                user.getPassword(),
                user.getBirth(),
                mapToGrantedAuthorities(user.getAuthorities())
        );
    }

    private static List<GrantedAuthority> mapToGrantedAuthorities(List<Authority> authorities) {
        return authorities.stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getName().name()))
                .collect(Collectors.toList());
    }
}
