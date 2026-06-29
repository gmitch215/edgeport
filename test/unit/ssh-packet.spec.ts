import { describe, expect, it } from 'vitest';
import { StreamFramedReader } from '../../src/core/framing';
import { buildPaddedBody, NoneCipher, unwrapBody } from '../../src/crypto/packet';

const streamOf = (b: Uint8Array) =>
	new ReadableStream<Uint8Array>({
		start(c) {
			c.enqueue(b);
			c.close();
		}
	});

describe('binary packet framing', () => {
	it('pads to an 8-byte multiple with >= 4 padding bytes', () => {
		for (let len = 0; len < 40; len++) {
			const body = buildPaddedBody(new Uint8Array(len), 8, true);
			const padLen = body[0]!;
			expect(padLen).toBeGreaterThanOrEqual(4);
			expect((4 + body.length) % 8).toBe(0); // length field counted
			expect(unwrapBody(body)).toHaveLength(len);
		}
	});

	it('aligns the encrypted portion when the length field is excluded', () => {
		const body = buildPaddedBody(new Uint8Array(10), 16, false);
		expect(body.length % 16).toBe(0);
	});

	it('NoneCipher seals then opens a payload unchanged', async () => {
		const payload = new TextEncoder().encode('the quick brown fox');
		const cipher = new NoneCipher();
		const wire = await cipher.seal(0, payload);
		const got = await cipher.open(0, new StreamFramedReader(streamOf(wire)));
		expect(new TextDecoder().decode(got)).toBe('the quick brown fox');
	});
});
