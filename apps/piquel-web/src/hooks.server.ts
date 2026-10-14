import { dev } from '$app/environment';
import { env } from '$env/dynamic/private';
import { AuthOrigin } from '@piquel/auth-sdk/server';

// Validated when the server starts: an invalid AUTH_ORIGIN stops it before it listens.
export const handle = AuthOrigin.parse(env.AUTH_ORIGIN, dev).handle;
