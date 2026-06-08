package org.finos.fluxnova.ai.mcp.security.securityconfigs;

import org.finos.fluxnova.ai.mcp.security.engine.EngineAuthenticationContextFilter;
import org.finos.fluxnova.bpm.engine.ProcessEngine;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Secures all MCP endpoints with OAuth2 Bearer Token (JWT) authentication.
 *
 * <p>JWT validation is performed by Spring Security's OAuth2 resource server support,
 * configured via {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}.
 * The engine identity bridge ({@link EngineAuthenticationContextFilter}) then
 * propagates the authenticated principal into the Fluxnova process engine's
 * identity context for all downstream authorization checks.</p>
 */
public class SecurityConfig {

    private final EngineAuthenticationContextFilter engineAuthContextFilter;

    public SecurityConfig(ProcessEngine processEngine) {
        this.engineAuthContextFilter = new EngineAuthenticationContextFilter(processEngine);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/mcp/**", "/sse/**")
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            )
            .addFilterAfter(engineAuthContextFilter, BearerTokenAuthenticationFilter.class)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
