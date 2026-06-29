// security + resilience: every cipher must round-trip exactly AND reject tampered packets
import { describe, expect, it } from 'vitest';
import { ProtocolError } from '../../src/core/errors';
import { StreamFramedReader } from '../../src/core/framing';
import { cipherSizes, concatBytes, createPacketCipher, type DirectionKeys } from '../../src/crypto';

const seq = (n: number) => new Uint8Array(n).map((_, i) => (i * 7 + 3) & 0xff);
const streamOf = (b: Uint8Array) =>
	new ReadableStream<Uint8Array>({
		start(c) {
			c.enqueue(b);
			c.close();
		}
	});

function keysFor(cipher: string, mac: string): DirectionKeys {
	const s = cipherSizes(cipher, mac);
	return { iv: seq(s.ivLen), key: seq(s.keyLen), macKey: seq(s.macKeyLen) };
}

const CASES: [string, string][] = [
	['aes256-gcm@openssh.com', ''],
	['aes128-gcm@openssh.com', ''],
	['chacha20-poly1305@openssh.com', ''],
	['aes256-ctr', 'hmac-sha2-256'],
	['aes128-ctr', 'hmac-sha2-512']
];

describe('cipher round-trip and tamper rejection', () => {
	for (const [cipher, mac] of CASES) {
		it(`${cipher}: seals and opens multiple packets in order`, async () => {
			const sender = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
			const receiver = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
			const payloads = [new Uint8Array(0), seq(1), seq(15), seq(16), seq(200)];
			const wires: Uint8Array[] = [];
			for (let i = 0; i < payloads.length; i++)
				wires.push(await sender.seal(i, payloads[i] as Uint8Array));
			const reader = new StreamFramedReader(streamOf(concatBytes(...wires)));
			for (let i = 0; i < payloads.length; i++) {
				const expected = payloads[i] as Uint8Array;
				expect([...(await receiver.open(i, reader))]).toEqual([...expected]);
			}
		});

		it(`${cipher}: rejects a tampered ciphertext`, async () => {
			const sender = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
			const receiver = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
			const wire = await sender.seal(0, seq(64));
			wire[wire.length - 1]! ^= 0xff; // flip a tag/MAC byte
			await expect(receiver.open(0, new StreamFramedReader(streamOf(wire)))).rejects.toBeInstanceOf(
				ProtocolError
			);
		});

		it(`${cipher}: rejects an out-of-order packet`, async () => {
			const sender = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
			const receiver = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
			await sender.seal(0, seq(32)); // advance the sender to counter/seq 1
			const second = await sender.seal(1, seq(32));
			// delivering the second packet first desyncs the GCM counter / chacha nonce / ctr state
			await expect(
				receiver.open(0, new StreamFramedReader(streamOf(second)))
			).rejects.toBeInstanceOf(ProtocolError);
		});
	}
});
