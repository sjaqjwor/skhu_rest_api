package kr.ac.skhu.security.controller;

import kr.ac.skhu.model.security.User;
import kr.ac.skhu.security.JwtAuthenticationRequest;
import kr.ac.skhu.security.JwtUser;
import kr.ac.skhu.security.repository.UserRepository;
import kr.ac.skhu.security.service.JwtUserDetailsServiceImpl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.mobile.device.Device;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import kr.ac.skhu.security.JwtTokenUtil;
import kr.ac.skhu.security.service.JwtAuthenticationResponse;

import javax.servlet.http.HttpServletRequest;

@RestController
public class AuthenticationRestController {

    private final Log logger = LogFactory.getLog(this.getClass());

    @Value("${jwt.header}")
    private String tokenHeader;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired // UserDetailService 상속 받은 클래스
    private JwtUserDetailsServiceImpl jwtUserDetailsService;

    // server:contextPath/auth 로 들어오는 request 정보를 기반으로 toekn 만들어서 response 로 리턴
    @RequestMapping(value = "${jwt.route.authentication.path}", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtAuthenticationRequest authenticationRequest, Device device) throws AuthenticationException {
        // Perform the security
        logger.info("아이디:"+authenticationRequest.getUsername());
        logger.info("아이디:"+authenticationRequest.getPassword());
        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getUsername(),
                        authenticationRequest.getPassword()
                )
        );
        logger.info("jun test " + authenticationRequest.getUsername());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        logger.info("jun test " + authenticationRequest.getUsername());
        // Reload password post-security so we can generate token    authenticationRequest.getName() == user의 loginId
        final UserDetails userDetails = jwtUserDetailsService.loadUserByLoginId(authenticationRequest.getUsername());
        final User user = userRepository.findByLoginId(authenticationRequest.getUsername());
        final String token = jwtTokenUtil.generateToken(userDetails, user, device); //유저 정보를 기반으로 토큰 생성

        // Return the token
        return ResponseEntity.ok(new JwtAuthenticationResponse(token));
    }
    // server:contextPath/refresh .. 저장되어 있는 token 정보를 기반으로, 발급이 가능한지 확인 후 refresh token 을 반환한다.
    @RequestMapping(value = "${jwt.route.authentication.refresh}", method = RequestMethod.GET)
    public ResponseEntity<?> refreshAndGetAuthenticationToken(HttpServletRequest request) {
        String token = request.getHeader(tokenHeader); //헤더의 토큰 분리
        String loginId = jwtTokenUtil.getLoginIdFromToken(token);
        JwtUser user = (JwtUser) jwtUserDetailsService.loadUserByLoginId(loginId);

        if (jwtTokenUtil.canTokenBeRefreshed(token,user.getBirth())) { //refresh 토큰 발급이 가능하다면
            String refreshedToken = jwtTokenUtil.refreshToken(token); //생성 후
            return ResponseEntity.ok(new JwtAuthenticationResponse(refreshedToken)); //발급
        } else {
            return ResponseEntity.badRequest().body(null);
        }
    }
}
