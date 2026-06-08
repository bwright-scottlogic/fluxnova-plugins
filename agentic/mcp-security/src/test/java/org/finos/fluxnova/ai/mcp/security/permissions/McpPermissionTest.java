package org.finos.fluxnova.ai.mcp.security.permissions;

import org.finos.fluxnova.bpm.engine.authorization.Resource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("McpPermission")
class McpPermissionTest {

    @Test
    @DisplayName("ACCESS should have value Integer.MAX_VALUE")
    void access_hasValueMaxInt() {
        // NOTE: The Permission contract states getValue() should return a power of 2.
        // Using Integer.MAX_VALUE makes ACCESS equivalent to the built-in Permissions.ALL,
        // which means granting ACCESS sets ALL permission bits. This is fine for the
        // current implementation of this resource, which only has a binary
        // access/no-access model per resource type — granularity comes from the resource
        // type (MCP, MCP_PROCESS_TOOLS, MCP_TASK_TOOLS), not from permission bits.
        assertEquals(Integer.MAX_VALUE, McpPermission.ACCESS.getValue());
    }

    @Test
    @DisplayName("both permissions should reference all three MCP resource types")
    void permissions_referenceAllMcpResourceTypes() {
        for (McpPermission perm : McpPermission.values()) {
            Resource[] types = perm.getTypes();
            assertEquals(3, types.length,
                    "Each permission should link to all three MCP resource types");
            assertSame(McpResource.MCP, types[0]);
            assertSame(McpResource.MCP_PROCESS_TOOLS, types[1]);
            assertSame(McpResource.MCP_TASK_TOOLS, types[2]);
        }
    }

    @Test
    @DisplayName("enum should have exactly two values")
    void enumHasTwoValues() {
        assertEquals(2, McpPermission.values().length);
    }

    @Test
    @DisplayName("valueOf should resolve correctly")
    void valueOf_resolvesCorrectly() {
        assertSame(McpPermission.NONE, McpPermission.valueOf("NONE"));
        assertSame(McpPermission.ACCESS, McpPermission.valueOf("ACCESS"));
    }
}
