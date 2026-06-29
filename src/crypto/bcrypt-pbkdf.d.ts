// minimal ambient types for the untyped bcrypt-pbkdf package (OpenBSD bcrypt_pbkdf)
declare module 'bcrypt-pbkdf' {
	/** Fills `key` with `keylen` bytes derived from `pass`/`salt` over `rounds`. */
	export function pbkdf(
		pass: Uint8Array,
		passlen: number,
		salt: Uint8Array,
		saltlen: number,
		key: Uint8Array,
		keylen: number,
		rounds: number
	): number;
	const _default: { pbkdf: typeof pbkdf };
	export default _default;
}
