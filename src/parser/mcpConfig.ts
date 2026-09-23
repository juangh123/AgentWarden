const MCP_CONFIG_FILENAMES = new Set([
  '.mcp.json',
  'claude_desktop_config.json',
  'cline_mcp_settings.json',
  'mcp-config.json',
  'mcp-servers.json',
  'mcp.json',
  'mcp_config.json',
  'mcp_servers.json',
  'mcp_settings.json',
]);

export type McpServersObject = Record<string, unknown>;

function isPlainObject(value: unknown): value is McpServersObject {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function getProjectMcpServers(value: McpServersObject): Array<[string, McpServersObject]> {
  const projects = isPlainObject(value.projects) ? value.projects : undefined;
  if (!projects) return [];

  const entries: Array<[string, McpServersObject]> = [];
  for (const [projectPath, project] of Object.entries(projects)) {
    if (!isPlainObject(project) || !isPlainObject(project.mcpServers)) continue;
    entries.push([projectPath, project.mcpServers]);
  }
  return entries;
}

export function isMcpConfigFilename(filePath: string): boolean {
  const filename = filePath.split(/[\\/]/).pop()?.toLowerCase() ?? '';
  return MCP_CONFIG_FILENAMES.has(filename) || /(^|[-_.])mcp([-_.]|$).*\.json$/i.test(filename);
}

/**
 * Return the server map from the MCP container shapes used by common clients.
 * Invalid values are ignored so callers can fail closed with SEC-MCP-003.
 */
export function extractMcpServersObject(value: unknown): McpServersObject | undefined {
  if (!isPlainObject(value)) return undefined;

  const mcp = isPlainObject(value.mcp) ? value.mcp : undefined;
  const customizations = isPlainObject(value.customizations) ? value.customizations : undefined;
  const vscode = customizations && isPlainObject(customizations.vscode)
    ? customizations.vscode
    : undefined;
  const devContainerMcp = vscode && isPlainObject(vscode.mcp) ? vscode.mcp : undefined;

  const candidates: Array<[string, unknown]> = [
    ['user', value.mcpServers],
    ['servers', value.servers],
    ['context_servers', value.context_servers],
    ['mcp', mcp?.servers],
    ['devcontainer', devContainerMcp?.servers],
  ];

  const merged: McpServersObject = {};
  let foundServerMap = false;
  for (const [scope, candidate] of candidates) {
    if (!isPlainObject(candidate)) continue;
    foundServerMap = true;
    for (const [serverName, serverConfig] of Object.entries(candidate)) {
      const outputName = Object.hasOwn(merged, serverName)
        ? `${scope}:${serverName}`
        : serverName;
      merged[outputName] = serverConfig;
    }
  }

  for (const [projectPath, servers] of getProjectMcpServers(value)) {
    foundServerMap = true;
    for (const [serverName, serverConfig] of Object.entries(servers)) {
      const outputName = Object.hasOwn(merged, serverName)
        ? `${projectPath}:${serverName}`
        : serverName;
      merged[outputName] = serverConfig;
    }
  }

  return foundServerMap ? merged : undefined;
}

/** Return whether a JSON object declares one of the supported MCP server-map locations. */
export function hasMcpServersContainer(value: unknown): boolean {
  if (!isPlainObject(value)) return false;

  const mcp = isPlainObject(value.mcp) ? value.mcp : undefined;
  const customizations = isPlainObject(value.customizations) ? value.customizations : undefined;
  const vscode = customizations && isPlainObject(customizations.vscode)
    ? customizations.vscode
    : undefined;
  const devContainerMcp = vscode && isPlainObject(vscode.mcp) ? vscode.mcp : undefined;

  return (
    Object.hasOwn(value, 'mcpServers') ||
    Object.hasOwn(value, 'servers') ||
    Object.hasOwn(value, 'context_servers') ||
    Boolean(mcp && Object.hasOwn(mcp, 'servers')) ||
    Boolean(devContainerMcp && Object.hasOwn(devContainerMcp, 'servers')) ||
    Object.values(isPlainObject(value.projects) ? value.projects : {}).some(
      (project) => isPlainObject(project) && Object.hasOwn(project, 'mcpServers'),
    )
  );
}
