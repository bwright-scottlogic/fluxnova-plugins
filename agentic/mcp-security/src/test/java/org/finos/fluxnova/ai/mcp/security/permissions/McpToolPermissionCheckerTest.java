package org.finos.fluxnova.ai.mcp.security.permissions;

import org.finos.fluxnova.bpm.engine.AuthorizationService;
import org.finos.fluxnova.bpm.engine.ProcessEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("McpToolPermissionChecker")
class McpToolPermissionCheckerTest {

    @Mock
    private ProcessEngine processEngine;

    @Mock
    private AuthorizationService authorizationService;

    private McpToolPermissionChecker checker;

    @BeforeEach
    void setUp() {
        lenient().when(processEngine.getAuthorizationService()).thenReturn(authorizationService);
        checker = new McpToolPermissionChecker(processEngine);
    }

    @Nested
    @DisplayName("isAuthorizedForToolCategory()")
    class IsAuthorizedForToolCategory {

        @Test
        @DisplayName("should return true when user is authorized for process tools")
        void authorizedForProcessTools_returnsTrue() {
            when(authorizationService.isUserAuthorized("admin", List.of("admins"),
                    McpPermission.ACCESS, McpResource.MCP_PROCESS_TOOLS))
                    .thenReturn(true);

            boolean result = checker.isAuthorizedForToolCategory(
                    "admin", List.of("admins"), McpResource.MCP_PROCESS_TOOLS);

            assertTrue(result);
        }

        @Test
        @DisplayName("should return false when user is not authorized for process tools")
        void notAuthorizedForProcessTools_returnsFalse() {
            when(authorizationService.isUserAuthorized("user", List.of("viewers"),
                    McpPermission.ACCESS, McpResource.MCP_PROCESS_TOOLS))
                    .thenReturn(false);

            boolean result = checker.isAuthorizedForToolCategory(
                    "user", List.of("viewers"), McpResource.MCP_PROCESS_TOOLS);

            assertFalse(result);
        }

        @Test
        @DisplayName("should return true when user is authorized for task tools")
        void authorizedForTaskTools_returnsTrue() {
            when(authorizationService.isUserAuthorized("admin", List.of("admins"),
                    McpPermission.ACCESS, McpResource.MCP_TASK_TOOLS))
                    .thenReturn(true);

            boolean result = checker.isAuthorizedForToolCategory(
                    "admin", List.of("admins"), McpResource.MCP_TASK_TOOLS);

            assertTrue(result);
        }

        @Test
        @DisplayName("should return false when user is not authorized for task tools")
        void notAuthorizedForTaskTools_returnsFalse() {
            when(authorizationService.isUserAuthorized("user", List.of(),
                    McpPermission.ACCESS, McpResource.MCP_TASK_TOOLS))
                    .thenReturn(false);

            boolean result = checker.isAuthorizedForToolCategory(
                    "user", List.of(), McpResource.MCP_TASK_TOOLS);

            assertFalse(result);
        }

        @Test
        @DisplayName("should delegate to engine authorization service for process tools")
        void delegatesToAuthorizationService_processTools() {
            checker.isAuthorizedForToolCategory("admin", List.of(), McpResource.MCP_PROCESS_TOOLS);

            verify(authorizationService).isUserAuthorized("admin", List.of(),
                    McpPermission.ACCESS, McpResource.MCP_PROCESS_TOOLS);
        }

        @Test
        @DisplayName("should delegate to engine authorization service for task tools")
        void delegatesToAuthorizationService_taskTools() {
            checker.isAuthorizedForToolCategory("admin", List.of(), McpResource.MCP_TASK_TOOLS);

            verify(authorizationService).isUserAuthorized("admin", List.of(),
                    McpPermission.ACCESS, McpResource.MCP_TASK_TOOLS);
        }

        @Test
        @DisplayName("should use ACCESS permission for all tool category checks")
        void usesAccessPermission() {
            checker.isAuthorizedForToolCategory("user", List.of(), McpResource.MCP_TASK_TOOLS);

            verify(authorizationService).isUserAuthorized(anyString(), anyList(),
                    eq(McpPermission.ACCESS), any());
        }

        @Test
        @DisplayName("should work for the general MCP resource type")
        void authorizedForMcp_returnsCorrectResult() {
            when(authorizationService.isUserAuthorized("admin", List.of(),
                    McpPermission.ACCESS, McpResource.MCP))
                    .thenReturn(true);

            boolean result = checker.isAuthorizedForToolCategory("admin", List.of(), McpResource.MCP);

            assertTrue(result);
        }

        @Test
        @DisplayName("should pass empty group list to authorization service")
        void emptyGroups_passesEmptyList() {
            checker.isAuthorizedForToolCategory("user", List.of(), McpResource.MCP_PROCESS_TOOLS);

            verify(authorizationService).isUserAuthorized(eq("user"), eq(List.of()), any(), any());
        }

        @Test
        @DisplayName("should propagate engine exceptions")
        void engineException_propagates() {
            when(authorizationService.isUserAuthorized(anyString(), anyList(), any(), any()))
                    .thenThrow(new RuntimeException("Engine unavailable"));

            assertThrows(RuntimeException.class, () ->
                    checker.isAuthorizedForToolCategory("user", List.of(), McpResource.MCP_PROCESS_TOOLS));
        }
    }
}
