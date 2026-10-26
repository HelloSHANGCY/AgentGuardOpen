export const RULE_TABS = ['features', 'strategies', 'test', 'history'];

export function ruleHash(tab = 'features', identifier = '', revision = '') {
  const page = RULE_TABS.includes(tab) ? tab : 'features';
  return '#/rules/' + page + (identifier ? '/' + encodeURIComponent(identifier) : '')
    + (identifier && revision ? '?revision=' + encodeURIComponent(revision) : '');
}

export function parseRuleHash(hash) {
  const [path, query = ''] = hash.split('?');
  const [name, page = 'features', ...parts] = path.replace(/^#\/?/, '').split('/');
  if (name !== 'rules' || !RULE_TABS.includes(page)) return null;
  try {
    return { tab: page, identifier: decodeURIComponent(parts.join('/')), revision: new URLSearchParams(query).get('revision') || '' };
  } catch { return null; }
}
