// shared encoding helpers for tests
export const fromHex = (s: string): Uint8Array =>
	new Uint8Array((s.replace(/\s+/g, '').match(/../g) ?? []).map((h) => parseInt(h, 16)));

export const toHex = (b: Uint8Array): string =>
	[...b].map((x) => x.toString(16).padStart(2, '0')).join('');

// base64url with no padding, for JWK key material
export const b64url = (b: Uint8Array): string => {
	let bin = '';
	for (const byte of b) bin += String.fromCharCode(byte);
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
