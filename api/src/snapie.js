import { jwtVerify } from 'jose';

// Verifies a "Sign in with Snapie" token: RS256, issuer + audience pinned, short expiry.
// `keys` is a jose key getter (createRemoteJWKSet in prod, createLocalJWKSet in tests).
export function makeSnapieVerifier({ keys, issuer, audience }) {
  return async (token) => (await jwtVerify(token, keys, { issuer, audience, algorithms: ['RS256'] })).payload;
}
