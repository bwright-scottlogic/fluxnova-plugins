package org.finos.fluxnova.ai.mcp.security.permissions;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("McpResource")
class McpResourceTest {

    @Test
    @DisplayName("MCP resource should have type id 22")
    void resourceType() {
        assertEquals(22, McpResource.MCP.resourceType());
    }

    @Test
    @DisplayName("MCP_PROCESS_TOOLS resource should have type id 23")
    void processToolsResourceType() {
        assertEquals(23, McpResource.MCP_PROCESS_TOOLS.resourceType());
    }

    @Test
    @DisplayName("MCP_TASK_TOOLS resource should have type id 24")
    void taskToolsResourceType() {
        assertEquals(24, McpResource.MCP_TASK_TOOLS.resourceType());
    }

    @Test
    @DisplayName("enum should have exactly three values")
    void enumHasThreeValues() {
        assertEquals(3, McpResource.values().length);
    }

    @Test
    @DisplayName("valueOf should resolve MCP correctly")
    void valueOf_mcp() {
        assertSame(McpResource.MCP, McpResource.valueOf("MCP"));
    }

    @Test
    @DisplayName("valueOf should resolve MCP_PROCESS_TOOLS correctly")
    void valueOf_processTools() {
        assertSame(McpResource.MCP_PROCESS_TOOLS, McpResource.valueOf("MCP_PROCESS_TOOLS"));
    }

    @Test
    @DisplayName("valueOf should resolve MCP_TASK_TOOLS correctly")
    void valueOf_taskTools() {
        assertSame(McpResource.MCP_TASK_TOOLS, McpResource.valueOf("MCP_TASK_TOOLS"));
    }

    @Test
    @DisplayName("resource names should match enum names")
    void resourceNames() {
        assertEquals("MCP", McpResource.MCP.resourceName());
        assertEquals("MCP_PROCESS_TOOLS", McpResource.MCP_PROCESS_TOOLS.resourceName());
        assertEquals("MCP_TASK_TOOLS", McpResource.MCP_TASK_TOOLS.resourceName());
    }

    @Test
    @DisplayName("resource type IDs should be unique")
    void resourceTypeIdsAreUnique() {
        long distinctIds = java.util.Arrays.stream(McpResource.values())
                .mapToInt(McpResource::resourceType)
                .distinct()
                .count();
        assertEquals(McpResource.values().length, distinctIds);
    }
}
