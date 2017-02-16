package kr.ac.skhu.security;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

    private static final long serialVersionUID = -8970718410437077606L;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // 유효성이 없는 토큰을 갖고 REST API 에 접근할 때 호출된다.
        // 401 Unauthorized response 을 보낸다.
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}