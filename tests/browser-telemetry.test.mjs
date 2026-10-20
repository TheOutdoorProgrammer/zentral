import assert from 'node:assert/strict';
import test from 'node:test';
import { privacyFilter } from '@nerdswhofish/browser-telemetry/privacy';

test('Faro drops private routes, error messages, users, and console content', () => {
  const filter = privacyFilter({
    app: { name: 'zentral', version: 'test', environment: 'test' },
    origin: 'https://zentral.example.test',
    routes: ['/accounts/login/'],
    assets: ['/static/dist/main.js'],
    operations: [],
  });
  const meta = {
    user: { email: 'private@example.test' },
    page: { url: 'https://zentral.example.test/devices/private-serial?code=secret' },
    sdk: { name: 'test', version: '1' },
    session: { id: 'opaque', attributes: { isSampled: 'true' } },
  };
  const result = filter({
    type: 'exception', meta,
    payload: {
      type: 'Error', value: 'secret private-serial', timestamp: new Date().toISOString(),
      stacktrace: { frames: [{ filename: '/secret/path.js', function: 'secret' }] },
    },
  });
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /private|secret/);
  assert.equal(result.meta.page.url, '/{other}');
  assert.equal(result.payload.value, 'Error');
  assert.equal(filter({ type: 'log', meta, payload: { message: 'secret' } }), null);
});
