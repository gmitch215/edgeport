import { connect } from 'cloudflare:sockets';

export default {
	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		// fallback probe path: GET /banner?host=..&port=.. reads the first line of a tcp peer
		if (url.pathname === '/banner') {
			const hostname = url.searchParams.get('host') ?? '127.0.0.1';
			const port = Number(url.searchParams.get('port') ?? '2222');
			const socket = connect({ hostname, port });
			try {
				const reader = socket.readable.getReader();
				const { value } = await reader.read();
				reader.releaseLock();
				const banner = new TextDecoder().decode(value ?? new Uint8Array());
				return new Response(banner.split('\r\n')[0] ?? '');
			} finally {
				await socket.close().catch(() => {});
			}
		}
		return new Response('edgeport test harness', { status: 200 });
	}
};
