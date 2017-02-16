package kr.ac.skhu.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Created by Junwoo on 2017-02-15.
 */
@Service
public class UserService {
    @Autowired
    private static PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public static String passwordEncoding(String password){
        String encodedPassword = new BCryptPasswordEncoder().encode(password);
        return encodedPassword;
    }
}
