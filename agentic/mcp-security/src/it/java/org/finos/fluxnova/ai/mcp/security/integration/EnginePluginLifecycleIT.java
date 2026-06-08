package org.finos.fluxnova.ai.mcp.security.integration;

import org.finos.fluxnova.ai.mcp.security.permissions.McpPermission;
import org.finos.fluxnova.ai.mcp.security.permissions.McpPermissionProvider;
import org.finos.fluxnova.ai.mcp.security.permissions.McpResource;
import org.finos.fluxnova.ai.mcp.security.permissions.McpSecurityEnginePlugin;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Integration test that exercises the full McpSecurityEnginePlugin lifecycle:
 * preInit + postProcessEngineBuild as it would happen in a real engine boot sequence.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("McpSecurityEnginePlugin Lifecycle Integration")
class EnginePluginLifecycleIT {

    @Mock
    private ProcessEngineConfigurationImpl configuration;

    @Mock
    private ProcessEngine processEngine;

    @Mock
    private AuthorizationService authorizationService;

    @Mock
    private AuthorizationQuery authorizationQuery;

    private McpSecurityEnginePlugin plugin;

    @BeforeEach
    void setUp() {
        plugin = new McpSecurityEnginePlugin();
    }

    @Test
    @DisplayName("full lifecycle: preInit registers provider, postBuild creates authorization for all resources")
    void fullLifecycle_registersAndCreatesAuth() {
        // Phase 1: preInit
        plugin.preInit(configuration);

        // Verify provider is registered
        ArgumentCaptor<McpPermissionProvider> providerCaptor =
                ArgumentCaptor.forClass(McpPermissionProvider.class);
        verify(configuration).setPermissionProvider(providerCaptor.capture());
        McpPermissionProvider registeredProvider = providerCaptor.getValue();

        // Verify the registered provider can resolve MCP permissions for all resource types
        for (McpResource resource : McpResource.values()) {
            assertEquals(McpPermission.ACCESS,
                    registeredProvider.getPermissionForName("ACCESS", resource.resourceType()),
                    "Provider should resolve ACCESS for resource type " + resource.resourceType());
            assertEquals(McpPermission.NONE,
                    registeredProvider.getPermissionForName("NONE", resource.resourceType()),
                    "Provider should resolve NONE for resource type " + resource.resourceType());
        }

        // Verify resource type registration for all MCP resource types
        for (McpResource resource : McpResource.values()) {
            assertSame(McpPermission.class,
                    ResourceTypeUtil.getPermissionEnums().get(resource.resourceType()),
                    "McpPermission class should be registered for resource type " + resource.resourceType());
        }

        // Phase 2: postProcessEngineBuild
        when(processEngine.getProcessEngineConfiguration()).thenReturn(configuration);
        when(configuration.isAuthorizationEnabled()).thenReturn(true);
        when(processEngine.getAuthorizationService()).thenReturn(authorizationService);
        when(authorizationService.createAuthorizationQuery()).thenReturn(authorizationQuery);
        when(authorizationQuery.groupIdIn(anyString())).thenReturn(authorizationQuery);
        when(authorizationQuery.resourceType(any(McpResource.class))).thenReturn(authorizationQuery);
        when(authorizationQuery.resourceId(anyString())).thenReturn(authorizationQuery);
        when(authorizationQuery.count()).thenReturn(0L);

        plugin.postProcessEngineBuild(processEngine);

        // Verify authorization was created for all three resource types
        ArgumentCaptor<AuthorizationEntity> authCaptor =
                ArgumentCaptor.forClass(AuthorizationEntity.class);
        verify(authorizationService, times(McpResource.values().length))
                .saveAuthorization(authCaptor.capture());

        List<AuthorizationEntity> created = authCaptor.getAllValues();
        assertEquals(McpResource.values().length, created.size());

        // All authorizations must have GRANT type, CAMUNDA_ADMIN group, and ANY resource id
        for (AuthorizationEntity auth : created) {
            assertEquals(Authorization.AUTH_TYPE_GRANT, auth.getAuthorizationType());
            assertEquals(Groups.CAMUNDA_ADMIN, auth.getGroupId());
            assertEquals(Authorization.ANY, auth.getResourceId());
        }

        // Each MCP resource type must be covered
        java.util.Set<Integer> resourceTypes = created.stream()
                .map(AuthorizationEntity::getResourceType)
                .collect(java.util.stream.Collectors.toSet());
        for (McpResource resource : McpResource.values()) {
            assertTrue(resourceTypes.contains(resource.resourceType()),
                    "Authorization should be created for resource type " + resource.resourceType());
        }
    }

    @Test
    @DisplayName("full lifecycle: preInit then postBuild with auth disabled skips authorization")
    void lifecycle_authDisabled_skipsAuthorization() {
        // Phase 1
        plugin.preInit(configuration);

        // Phase 2
        when(processEngine.getProcessEngineConfiguration()).thenReturn(configuration);
        when(configuration.isAuthorizationEnabled()).thenReturn(false);

        plugin.postProcessEngineBuild(processEngine);

        verify(authorizationService, never()).saveAuthorization(any());
    }

    @Test
    @DisplayName("full lifecycle: idempotent — existing authorization prevents duplicate")
    void lifecycle_idempotent() {
        // Phase 1
        plugin.preInit(configuration);

        // Phase 2 — first time
        when(processEngine.getProcessEngineConfiguration()).thenReturn(configuration);
        when(configuration.isAuthorizationEnabled()).thenReturn(true);
        when(processEngine.getAuthorizationService()).thenReturn(authorizationService);
        when(authorizationService.createAuthorizationQuery()).thenReturn(authorizationQuery);
        when(authorizationQuery.groupIdIn(anyString())).thenReturn(authorizationQuery);
        when(authorizationQuery.resourceType(any(McpResource.class))).thenReturn(authorizationQuery);
        when(authorizationQuery.resourceId(anyString())).thenReturn(authorizationQuery);

        // Simulate: authorization already exists
        when(authorizationQuery.count()).thenReturn(1L);

        plugin.postProcessEngineBuild(processEngine);

        verify(authorizationService, never()).saveAuthorization(any());
    }
}
