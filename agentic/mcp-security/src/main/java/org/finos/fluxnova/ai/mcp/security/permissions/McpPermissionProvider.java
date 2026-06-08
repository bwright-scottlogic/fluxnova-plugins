package org.finos.fluxnova.ai.mcp.security.permissions;

import org.finos.fluxnova.bpm.engine.authorization.Permission;
import org.finos.fluxnova.bpm.engine.impl.cfg.auth.DefaultPermissionProvider;

public class McpPermissionProvider extends DefaultPermissionProvider {

    private boolean isMcpResourceType(int resourceType) {
        for (McpResource r : McpResource.values()) {
            if (r.resourceType() == resourceType) return true;
        }
        return false;
    }

    @Override
    public Permission getPermissionForName(String name, int resourceType) {
        if (isMcpResourceType(resourceType)) {
            for (McpPermission p : McpPermission.values()) {
                if (p.getName().equals(name)) return p;
            }
        }
        return super.getPermissionForName(name, resourceType);
    }

    @Override
    public Permission[] getPermissionsForResource(int resourceType) {
        if (isMcpResourceType(resourceType)) {
            return McpPermission.values();
        }
        return super.getPermissionsForResource(resourceType);
    }

    @Override
    public String getNameForResource(int resourceType) {
        for (McpResource r : McpResource.values()) {
            if (r.resourceType() == resourceType) return r.resourceName();
        }
        return super.getNameForResource(resourceType);
    }
}
