// the MIME builder: plain, html-only, multipart alternative, raw passthrough
import { describe, expect, it } from 'vitest';
import { buildMime } from '../../src/smtp/mime';

const decode = (b: Uint8Array) => new TextDecoder().decode(b);

describe('buildMime', () => {
	it('builds a text/plain message with required headers', () => {
		const out = decode(buildMime({ from: 'a@x', to: 'b@y', subject: 'Hi', text: 'hello' }));
		expect(out).toContain('From: a@x');
		expect(out).toContain('To: b@y');
		expect(out).toContain('Subject: Hi');
		expect(out).toContain('hello');
		expect(out).toContain('\r\n\r\n'); // header/body separator
	});

	it('builds multipart/alternative when both text and html are present', () => {
		const out = decode(
			buildMime({ from: 'a@x', to: ['b@y', 'c@z'], subject: 'M', text: 't', html: '<b>h</b>' })
		);
		expect(out.toLowerCase()).toContain('multipart/alternative');
		expect(out).toContain('<b>h</b>');
		expect(out).toContain('To: b@y, c@z');
	});

	it('builds an html-only message', () => {
		const out = decode(buildMime({ from: 'a@x', to: 'b@y', subject: 'H', html: '<p>x</p>' }));
		expect(out.toLowerCase()).toContain('text/html');
	});

	it('passes a raw message through verbatim', () => {
		const raw = new TextEncoder().encode('Raw: yes\r\n\r\nbody');
		expect(decode(buildMime({ from: 'a@x', to: 'b@y', subject: 'ignored', raw }))).toBe(
			'Raw: yes\r\n\r\nbody'
		);
	});
});
