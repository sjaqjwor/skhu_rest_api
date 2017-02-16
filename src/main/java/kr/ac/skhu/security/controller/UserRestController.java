package kr.ac.skhu.security.controller;

import kr.ac.skhu.model.security.User;
import kr.ac.skhu.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import kr.ac.skhu.security.JwtTokenUtil;

import javax.servlet.http.HttpServletRequest;

@RestController
public class UserRestController {

    @Value("${jwt.header}")
    private String tokenHeader;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private UserRepository userRepository;

    @RequestMapping(value = "user", method = RequestMethod.GET)
    public User getAuthenticatedUser(HttpServletRequest request) {
        String token = request.getHeader(tokenHeader);
        String loginId = jwtTokenUtil.getLoginIdFromToken(token);
        User user = userRepository.findByLoginId(loginId);
        return user;
    }
}
