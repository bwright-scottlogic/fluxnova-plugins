package org.finos.fluxnova.ai.mcp.security.permissions;

import org.finos.fluxnova.bpm.engine.AuthorizationService;
import org.finos.fluxnova.bpm.engine.ProcessEngine;
import org.finos.fluxnova.bpm.engine.authorization.Authorization;
import org.finos.fluxnova.bpm.engine.authorization.AuthorizationQuery;
import org.finos.fluxnova.bpm.engine.authorization.Groups;
import org.finos.fluxnova.bpm.engine.impl.cfg.ProcessEngineConfigurationImpl;
import org.finos.fluxnova.bpm.engine.impl.persistence.entity.AuthorizationEntity;
import org.finos.fluxnova.bpm.engine.impl.util.ResourceTypeUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("McpSecurityEnginePlugin")
class McpSecurityEnginePluginTest {

    private McpSecurityEnginePlugin plugin;

    @Mock
    private ProcessEngineConfigurationImpl configuration;

    @Mock
    private ProcessEngine processEngine;

    @Mock
    private AuthorizationService authorizationService;

    @Mock
    private AuthorizationQuery authorizationQuery;

    @BeforeEach
    void setUp() {
        plugin = new McpSecurityEnginePlugin();
    }

    @Nested
    @DisplayName("preInit()")
    class PreInit {

        @Test
        @DisplayName("should set McpPermissionProvider on configuration")
        void setsPermissionProvider() {
            plugin.preInit(configuration);

            ArgumentCaptor<McpPermissionProvider> captor =
                    ArgumentCaptor.forClass(McpPermissionProvider.class);
            verify(configuration).setPermissionProvider(captor.capture());
            assertInstanceOf(McpPermissionProvider.class, captor.getValue());
        }

        @Test
        @DisplayName("should register McpPermission enum for all three MCP resource types")
        void registersPermissionEnumsForAllResourceTypes() {
            plugin.preInit(configuration);

            for (McpResource resource : McpResource.values()) {
                Class<?> registered = ResourceTypeUtil.getPermissionEnums()
                        .get(resource.resourceType());
                assertSame(McpPermission.class, registered,
                        "McpPermission enum should be registered for resource type "
                                + resource.resourceType() + " (" + resource.resourceName() + ")");
            }
        }

        @Test
        @DisplayName("should register McpPermission enum for MCP resource type 22")
        void registersPermissionEnumForMcp() {
            plugin.preInit(configuration);

            Class<?> registered = ResourceTypeUtil.getPermissionEnums()
                    .get(McpResource.MCP.resourceType());
            assertSame(McpPermission.class, registered);
        }

        @Test
        @DisplayName("should register McpPermission enum for MCP_PROCESS_TOOLS resource type 23")
        void registersPermissionEnumForProcessTools() {
            plugin.preInit(configuration);

            Class<?> registered = ResourceTypeUtil.getPermissionEnums()
                    .get(McpResource.MCP_PROCESS_TOOLS.resourceType());
            assertSame(McpPermission.class, registered);
        }

        @Test
        @DisplayName("should register McpPermission enum for MCP_TASK_TOOLS resource type 24")
        void registersPermissionEnumForTaskTools() {
            plugin.preInit(configuration);

            Class<?> registered = ResourceTypeUtil.getPermissionEnums()
                    .get(McpResource.MCP_TASK_TOOLS.resourceType());
            assertSame(McpPermission.class, registered);
        }
    }

    @Nested
    @DisplayName("postProcessEngineBuild()")
    class PostProcessEngineBuild {

        @BeforeEach
        void setUpMocks() {
            lenient().when(processEngine.getAuthorizationService()).thenReturn(authorizationService);
            lenient().when(authorizationService.createAuthorizationQuery()).thenReturn(authorizationQuery);
            lenient().when(authorizationQuery.groupIdIn(anyString())).thenReturn(authorizationQuery);
            lenient().when(authorizationQuery.resourceType(any(McpResource.class))).thenReturn(authorizationQuery);
            lenient().when(authorizationQuery.resourceId(anyString())).thenReturn(authorizationQuery);
        }

        @Test
        @DisplayName("should skip when authorization is not enabled")
        void authorizationDisabled_skips() {
            when(processEngine.getProcessEngineConfiguration()).thenReturn(configuration);
            when(configuration.isAuthorizationEnabled()).thenReturn(false);

            plugin.postProcessEngineBuild(processEngine);

            verify(authorizationService, never()).saveAuthorization(any());
            verify(authorizationService, never()).createAuthorizationQuery();
        }

        @Test
        @DisplayName("should create admin authorization for all three resource types when none exist")
        void noExistingAuth_createsAdminAuthForAllResources() {
            when(processEngine.getProcessEngineConfiguration()).thenReturn(configuration);
            when(configuration.isAuthorizationEnabled()).thenReturn(true);
            when(authorizationQuery.count()).thenReturn(0L);

            plugin.postProcessEngineBuild(processEngine);

            ArgumentCaptor<AuthorizationEntity> captor =
                    ArgumentCaptor.forClass(AuthorizationEntity.class);
            verify(authorizationService, times(3)).saveAuthorization(captor.capture());

            List<AuthorizationEntity> saved = captor.getAllValues();
            Set<Integer> resourceTypes = saved.stream()
                    .map(AuthorizationEntity::getResourceType)
                    .collect(Collectors.toSet());
            assertEquals(
                    Set.of(McpResource.MCP.resourceType(),
                            McpResource.MCP_PROCESS_TOOLS.resourceType(),
                            McpResource.MCP_TASK_TOOLS.resourceType()),
                    resourceTypes,
                    "Should create authorization for all three MCP resource types"
            );
        }

        @Test
        @DisplayName("all created authorizations should target camunda-admin group")
        void createdAuth_targetsAdminGroup() {
            when(processEngine.getProcessEngineConfiguration()).thenReturn(configuration);
            when(configuration.isAuthorizationEnabled()).thenReturn(true);
            when(authorizationQuery.count()).thenReturn(0L);

            plugin.postProcessEngineBuild(processEngine);

            ArgumentCaptor<AuthorizationEntity> captor =
                    ArgumentCaptor.forClass(AuthorizationEntity.class);
            verify(authorizationService, times(3)).saveAuthorization(captor.capture());

            for (AuthorizationEntity saved : captor.getAllValues()) {
                assertEquals(Groups.CAMUNDA_ADMIN, saved.getGroupId());
                assertEquals(Authorization.ANY, saved.getResourceId());
                assertEquals(Authorization.AUTH_TYPE_GRANT, saved.getAuthorizationType());
            }
        }

        @Test
        @DisplayName("should query for existing authorization per resource type")
        void queriesAuthorizationPerResourceType() {
            when(processEngine.getProcessEngineConfiguration()).thenReturn(configuration);
            when(configuration.isAuthorizationEnabled()).thenReturn(true);
            when(authorizationQuery.count()).thenReturn(0L);

            plugin.postProcessEngineBuild(processEngine);

            verify(authorizationQuery, times(3)).groupIdIn(Groups.CAMUNDA_ADMIN);
            verify(authorizationQuery).resourceType(McpResource.MCP);
            verify(authorizationQuery).resourceType(McpResource.MCP_PROCESS_TOOLS);
            verify(authorizationQuery).resourceType(McpResource.MCP_TASK_TOOLS);
            verify(authorizationQuery, times(3)).resourceId(Authorization.ANY);
        }

        @Test
        @DisplayName("should NOT create authorization when all already exist")
        void existingAuth_doesNotCreate() {
            when(processEngine.getProcessEngineConfiguration()).thenReturn(configuration);
            when(configuration.isAuthorizationEnabled()).thenReturn(true);
            when(authorizationQuery.count()).thenReturn(1L);

            plugin.postProcessEngineBuild(processEngine);

            verify(authorizationService, never()).saveAuthorization(any());
        }

        @Test
        @DisplayName("should NOT create authorization when multiple already exist per resource")
        void multipleExistingAuth_doesNotCreate() {
            when(processEngine.getProcessEngineConfiguration()).thenReturn(configuration);
            when(configuration.isAuthorizationEnabled()).thenReturn(true);
            when(authorizationQuery.count()).thenReturn(5L);

            plugin.postProcessEngineBuild(processEngine);

            verify(authorizationService, never()).saveAuthorization(any());
        }

        @Test
        @DisplayName("all created authorizations should grant ACCESS permission")
        void createdAuth_grantsAccessPermission() {
            when(processEngine.getProcessEngineConfiguration()).thenReturn(configuration);
            when(configuration.isAuthorizationEnabled()).thenReturn(true);
            when(authorizationQuery.count()).thenReturn(0L);

            plugin.postProcessEngineBuild(processEngine);

            ArgumentCaptor<AuthorizationEntity> captor =
                    ArgumentCaptor.forClass(AuthorizationEntity.class);
            verify(authorizationService, times(3)).saveAuthorization(captor.capture());

            for (AuthorizationEntity saved : captor.getAllValues()) {
                assertTrue(
                        (saved.getPermissions() & McpPermission.ACCESS.getValue()) == McpPermission.ACCESS.getValue(),
                        "Authorization should grant ACCESS permission for resource type " + saved.getResourceType()
                );
            }
        }
    }
}
