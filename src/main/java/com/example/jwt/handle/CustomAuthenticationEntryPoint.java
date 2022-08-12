package com.example.jwt.handle;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        if(response.getStatus() != 401) {
            response.setStatus(403);
        }
        log.info("Not authentication {}", response.getStatus());
        Map<String, String> error = new HashMap<>();
        error.put("status", String.valueOf(response.getStatus()));
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}
