package kr.ac.skhu.security;

import java.util.Collection;
import java.util.Date;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class JwtUser implements UserDetails {

    private final String loginId;
    private final String username;
    private final String password;
    private final Date birth;

    private final Collection<? extends GrantedAuthority> authorities;
    private final boolean enabled;

    public JwtUser(
            String loginId,
            String username,
            String password,
            Date birth,
            Collection<? extends GrantedAuthority> authorities
    ) {
        this.loginId = loginId;
        this.username = username;
        this.password = password;
        this.birth=birth;
        this.authorities = authorities;
        this.enabled = true;
    }
    @JsonIgnore
    public String getLoginId() {
        return loginId;
    }

    @JsonIgnore
    public Date getBirth() {
        return birth;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
