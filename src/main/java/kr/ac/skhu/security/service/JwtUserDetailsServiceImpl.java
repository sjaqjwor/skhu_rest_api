package kr.ac.skhu.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import kr.ac.skhu.model.security.User;
import kr.ac.skhu.security.JwtUserFactory;
import kr.ac.skhu.security.repository.UserRepository;

@Service
public class JwtUserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    /* authenticationManager.authenticate 에서 로그인 처리할 때 사용되는 메소드  */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByLoginId(username);

        if (user == null) {
            throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
        } else {
            return JwtUserFactory.create(user);
        }
    }
    /* 로그인 아이디를 반환하는 서비스  */
    public UserDetails loadUserByLoginId(String loginId) throws UsernameNotFoundException {
        User user = userRepository.findByLoginId(loginId);

        if (user == null) {
            throw new UsernameNotFoundException(String.format("No user found with loginId '%s'.", loginId));
        } else {
            return JwtUserFactory.create(user);
        }
    }
}
