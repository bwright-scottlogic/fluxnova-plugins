package org.finos.fluxnova.ai.mcp.security.permissions;

import org.finos.fluxnova.bpm.engine.ProcessEngine;

import java.util.List;

/**
 * Service for checking fine-grained MCP tool-category permissions against the
 * Fluxnova engine authorization service.
 *
 * <p>The {@link org.finos.fluxnova.ai.mcp.security.engine.EngineAuthenticationContextFilter}
 * provides a gateway check for general {@link McpResource#MCP} access on every request.
 * This checker provides the next layer of granularity: individual tool categories
 * ({@link McpResource#MCP_PROCESS_TOOLS}, {@link McpResource#MCP_TASK_TOOLS}) can
 * be checked at tool-invocation time.</p>
 *
 * <p>Inject this bean into tool implementations or MCP interceptors to enforce
 * per-category access control:</p>
 * <pre>{@code
 * if (!permissionChecker.isAuthorizedForToolCategory(userId, groupIds, McpResource.MCP_PROCESS_TOOLS)) {
 *     throw new AccessDeniedException("Not authorized to invoke process tools");
 * }
 * }</pre>
 */
public class McpToolPermissionChecker {

    private final ProcessEngine processEngine;

    public McpToolPermissionChecker(ProcessEngine processEngine) {
        this.processEngine = processEngine;
    }

    /**
     * Returns {@code true} if the given user (and any of their groups) has the
     * {@link McpPermission#ACCESS} permission on the specified MCP tool-category resource.
     *
     * @param userId       the Fluxnova user ID of the authenticated caller
     * @param groupIds     the Fluxnova group IDs the user belongs to
     * @param toolCategory the {@link McpResource} representing the tool category to check
     * @return {@code true} if authorized, {@code false} otherwise
     */
    public boolean isAuthorizedForToolCategory(String userId, List<String> groupIds, McpResource toolCategory) {
        return processEngine.getAuthorizationService()
                .isUserAuthorized(userId, groupIds, McpPermission.ACCESS, toolCategory);
    }
}
