export const DEPLOYMENT_PAGES = ['architecture', 'methods'];
export const DEPLOYMENT_METHODS = ['docker', 'source'];

export function deploymentHash(page = 'architecture', method = 'docker') {
  return page === 'methods' && DEPLOYMENT_METHODS.includes(method)
    ? '#/deployment/methods/' + method : '#/deployment';
}

export function parseDeploymentHash(hash) {
  const parts = String(hash || '').replace(/^#\/?/, '').split('/').filter(Boolean);
  if (parts[0] === 'range') return { page: 'architecture', method: 'docker' };
  if (parts[0] !== 'deployment') return null;
  if (parts.length === 1 || (parts.length === 2 && parts[1] === 'architecture')) {
    return { page: 'architecture', method: 'docker' };
  }
  if (parts[1] === 'methods' && parts.length <= 3) {
    const method = parts[2] || 'docker';
    if (DEPLOYMENT_METHODS.includes(method)) return { page: 'methods', method };
  }
  return null;
}
