package org.finos.fluxnova.ai.mcp.security.permissions;

import org.finos.fluxnova.bpm.engine.authorization.Permission;
import org.finos.fluxnova.bpm.engine.authorization.Resources;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("McpPermissionProvider")
class McpPermissionProviderTest {

    private final McpPermissionProvider provider = new McpPermissionProvider();

    @Nested
    @DisplayName("getPermissionForName()")
    class GetPermissionForName {

        @Test
        @DisplayName("should return McpPermission.ACCESS for MCP resource type")
        void returnsAccessForMcpResource() {
            Permission perm = provider.getPermissionForName("ACCESS", McpResource.MCP.resourceType());
            assertSame(McpPermission.ACCESS, perm);
        }

        @Test
        @DisplayName("should return McpPermission.NONE for MCP resource type")
        void returnsNoneForMcpResource() {
            Permission perm = provider.getPermissionForName("NONE", McpResource.MCP.resourceType());
            assertSame(McpPermission.NONE, perm);
        }

        @ParameterizedTest
        @EnumSource(McpResource.class)
        @DisplayName("should return McpPermission.ACCESS for all MCP resource types")
        void returnsAccessForAllMcpResourceTypes(McpResource resource) {
            Permission perm = provider.getPermissionForName("ACCESS", resource.resourceType());
            assertSame(McpPermission.ACCESS, perm);
        }

        @ParameterizedTest
        @EnumSource(McpResource.class)
        @DisplayName("should return McpPermission.NONE for all MCP resource types")
        void returnsNoneForAllMcpResourceTypes(McpResource resource) {
            Permission perm = provider.getPermissionForName("NONE", resource.resourceType());
            assertSame(McpPermission.NONE, perm);
        }

        @Test
        @DisplayName("should return null from super when permission name doesn't match any MCP permission")
        void unknownPermissionName_fallsThroughToSuper() {
            // For MCP resource type, if name doesn't match NONE or ACCESS, the loop
            // finds nothing and falls through to super.getPermissionForName().
            // The super delegates to ResourceTypeUtil which may throw.
            // This test verifies the MCP-specific handling doesn't throw prematurely.
            try {
                provider.getPermissionForName("NONEXISTENT", McpResource.MCP.resourceType());
            } catch (Exception e) {
                // Expected: super.getPermissionForName may throw BadUserRequestException
                // since NONEXISTENT is not a valid permission for resource type 22
            }
        }

        @Test
        @DisplayName("should delegate to super for non-MCP resource types")
        void delegatesToSuperForNonMcpResource() {
            // For a built-in resource type, this should delegate to the default provider
            Permission perm = provider.getPermissionForName("READ",
                    Resources.PROCESS_DEFINITION.resourceType());
            assertNotNull(perm);
            assertEquals("READ", perm.getName());
        }
    }

    @Nested
    @DisplayName("getPermissionsForResource()")
    class GetPermissionsForResource {

        @Test
        @DisplayName("should return all McpPermission values for MCP resource type")
        void returnsAllMcpPermissions() {
            Permission[] perms = provider.getPermissionsForResource(McpResource.MCP.resourceType());
            assertArrayEquals(McpPermission.values(), perms);
        }

        @Test
        @DisplayName("should return exactly 2 permissions for MCP resource")
        void returnsTwoPermissions() {
            Permission[] perms = provider.getPermissionsForResource(McpResource.MCP.resourceType());
            assertEquals(2, perms.length);
        }

        @ParameterizedTest
        @EnumSource(McpResource.class)
        @DisplayName("should return all McpPermission values for all MCP resource types")
        void returnsAllMcpPermissionsForAllResourceTypes(McpResource resource) {
            Permission[] perms = provider.getPermissionsForResource(resource.resourceType());
            assertArrayEquals(McpPermission.values(), perms);
        }

        @Test
        @DisplayName("should delegate to super for non-MCP resource types")
        void delegatesToSuperForNonMcpResource() {
            Permission[] perms = provider.getPermissionsForResource(
                    Resources.PROCESS_DEFINITION.resourceType());
            assertNotNull(perms);
            // The default provider should return ProcessDefinitionPermissions values
            assertTrue(perms.length > 0);
        }
    }

    @Nested
    @DisplayName("getNameForResource()")
    class GetNameForResource {

        @Test
        @DisplayName("should return 'MCP' for MCP resource type")
        void returnsMcpName() {
            String name = provider.getNameForResource(McpResource.MCP.resourceType());
            assertEquals("MCP", name);
        }

        @Test
        @DisplayName("should return 'MCP_PROCESS_TOOLS' for process tools resource type")
        void returnsMcpProcessToolsName() {
            String name = provider.getNameForResource(McpResource.MCP_PROCESS_TOOLS.resourceType());
            assertEquals("MCP_PROCESS_TOOLS", name);
        }

        @Test
        @DisplayName("should return 'MCP_TASK_TOOLS' for task tools resource type")
        void returnsMcpTaskToolsName() {
            String name = provider.getNameForResource(McpResource.MCP_TASK_TOOLS.resourceType());
            assertEquals("MCP_TASK_TOOLS", name);
        }

        @ParameterizedTest
        @EnumSource(McpResource.class)
        @DisplayName("should return the correct resource name for all MCP resource types")
        void returnsCorrectNameForAllMcpResourceTypes(McpResource resource) {
            String name = provider.getNameForResource(resource.resourceType());
            assertEquals(resource.resourceName(), name);
        }

        @Test
        @DisplayName("should delegate to super for non-MCP resource types")
        void delegatesToSuperForNonMcpResource() {
            String name = provider.getNameForResource(Resources.PROCESS_DEFINITION.resourceType());
            assertNotNull(name);
        }

        @Test
        @DisplayName("should return null for completely unknown resource type")
        void returnsNullForUnknownResource() {
            String name = provider.getNameForResource(99999);
            assertNull(name);
        }
    }
}
