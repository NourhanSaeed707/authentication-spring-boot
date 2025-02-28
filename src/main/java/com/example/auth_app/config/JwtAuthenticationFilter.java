package com.example.auth_app.config;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

//JwtAuthenticationFilter -> It's the first filter that intercept the request i want to intercept request each time user make a request
//HttpServletRequest request -> that contains request
//HttpServletResponse response-> that contains request
// FilterChain -> it's chain responsibility design pattern that contains other filters. and it will call the next filter in the chain.

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response,@NonNull FilterChain filterChain) throws ServletException, IOException {
        // When we make a call we need to path jwt token to header (Authorization) so here we're trying to extract this header
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        // I want to check first check token: By check that I have authHeader (Authorization header that have token) and
        // token starts with Bearer if it's not do the next filter and return.
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
           filterChain.doFilter(request, response);
           return;
        }
        // I want to get JWT without Bearer
        jwt = authHeader.substring(7);
        // I want to extract email from JWT token
        userEmail = jwtService.extractUsername(jwt);
        // we first check that we have user and user not authenticated because it he authenticated we don't need to make the whole
        // authentication process again SecurityContextHolder.getContext().getAuthentication() check is user authenticated or not.
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
           UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
           if(jwtService.isTokenValid(jwt, userDetails)) {
               
           }
        }
    }
}
