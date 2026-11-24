/** Type-only fixture for #220: the object and MCP seams a mesh adapter uses. Run by `npm run typecheck`. */
import { createDuplexPeer, createObjectsServer, type ObjectsWho } from '@johnhenry/wsh/objects';
import { serveMcpOverDuplex, webmcpTools, type McpMessage } from '@johnhenry/wsh/page';
import { permits } from '@johnhenry/wsh/capabilities';

export function seams(window: Parameters<typeof webmcpTools>[0]['window'], send: (m: object) => void): void {
  const peer = createDuplexPeer({ send, who: { username: 'mesh', podId: 'A'.repeat(43) }, permit: (root, op) => permits(['objects:window:get'], { kind: 'objects', root, op }) });
  const server = createObjectsServer({
    roots: { window: {} },
    authorize: (who: ObjectsWho) => who.podId !== undefined || who.fingerprint !== null,
  });
  server.attach(peer, { who: { podId: 'A'.repeat(43) } });
  const handler = webmcpTools({ window, allow: ['search'] });
  const session = serveMcpOverDuplex(handler, { send: (m: McpMessage) => { void m; }, who: { podId: 'A'.repeat(43) }, permits: (req) => permits(['mcp:search'], req as never), maxMessageBytes: 4096 });
  session.receive({ jsonrpc: '2.0', id: 1, method: 'ping' });
  const closed: boolean = session.closed;
  session.close('done');
  void closed;
}
