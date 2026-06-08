package org.finos.fluxnova.ai.mcp.security.securityconfigs;

import org.finos.fluxnova.bpm.engine.AuthorizationService;
import org.finos.fluxnova.bpm.engine.IdentityService;
import org.finos.fluxnova.bpm.engine.ProcessEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("SecurityConfig")
class SecurityConfigTest {

    @Mock
    private ProcessEngine processEngine;

    @Mock
    private IdentityService identityService;

    @Test
    @DisplayName("constructor should create engine context filter from process engine")
    void constructor_createsComponents() {
        // SecurityConfig constructor creates EngineAuthenticationContextFilter.
        // No processEngine methods are called at construction time.
        SecurityConfig config = new SecurityConfig(processEngine);

        assertNotNull(config);
    }

    @Nested
    @WebMvcTest
    @ContextConfiguration(classes = SecurityConfigTest.SecurityFilterChainTests.TestConfig.class)
    @DisplayName("securityFilterChain(HttpSecurity)")
    class SecurityFilterChainTests {

        @Autowired
        private SecurityFilterChain securityFilterChain;

        @Test
        @DisplayName("should return a non-null SecurityFilterChain")
        void returnsNonNull() {
            assertNotNull(securityFilterChain);
        }

        @Test
        @DisplayName("should match /mcp/** paths")
        void matchesMcpPaths() {
            assertTrue(securityFilterChain.matches(new MockHttpServletRequest("GET", "/mcp/test")));
        }

        @Test
        @DisplayName("should match /sse/** paths")
        void matchesSsePaths() {
            assertTrue(securityFilterChain.matches(new MockHttpServletRequest("GET", "/sse/events")));
        }

        @Test
        @DisplayName("should not match non-MCP/SSE paths")
        void doesNotMatchOtherPaths() {
            assertFalse(securityFilterChain.matches(new MockHttpServletRequest("GET", "/api/health")));
        }

        @Configuration
        @Import(SecurityConfig.class)
        static class TestConfig {

            @Bean
            ProcessEngine processEngine() {
                ProcessEngine engine = mock(ProcessEngine.class);
                IdentityService identityService = mock(IdentityService.class);
                AuthorizationService authorizationService = mock(AuthorizationService.class);
                when(engine.getIdentityService()).thenReturn(identityService);
                when(engine.getAuthorizationService()).thenReturn(authorizationService);
                return engine;
            }

            @Bean
            JwtDecoder jwtDecoder() {
                return mock(JwtDecoder.class);
            }

            @Bean
            StubController stubController() {
                return new StubController();
            }
        }

        @RestController
        static class StubController {
            @GetMapping("/mcp/test")
            public String mcpTest() {
                return "ok";
            }
        }
    }
}
