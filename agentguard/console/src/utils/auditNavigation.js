export function auditHash(identifier = '') {
  return identifier ? '#/audit/sessions/' + encodeURIComponent(identifier) : '#/audit';
}

// 保留旧书签；所有会话详情都归入运行审计。
export function parseAuditHash(hash) {
  const [name, ...parts] = hash.replace(/^#\/?/, '').split('/');
  if (name === 'events' || (name === 'audit' && !parts.filter(Boolean).length)) {
    return { page: 'events', identifier: '' };
  }
  if (name !== 'chain' && !(name === 'audit' && parts.shift() === 'sessions')) return null;
  try {
    const identifier = decodeURIComponent(parts.join('/'));
    return { page: identifier ? 'chain' : 'events', identifier };
  } catch {
    return null;
  }
}
