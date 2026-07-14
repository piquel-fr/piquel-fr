export function safeReturnTo(value: string | null): string {
  if (!value || value.length > 512 || !value.startsWith('/') || value.startsWith('//') || value.includes('#')) return '';
  return value;
}

export function authorizationDestination(transaction: string, returnTo: string): string {
  if (transaction) return `/authorize?transaction=${encodeURIComponent(transaction)}`;
  return safeReturnTo(returnTo) || '/security';
}
