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

test('Family Setup RUM keeps the route but discards pairing fragments and device content', () => {
  const filter = privacyFilter({
    app: { name: 'zentral', version: 'test', environment: 'test' },
    origin: 'https://zentral.example.test',
    routes: ['/public/mdm/family-setup/'],
    assets: ['/static/dist/family_setup.js'],
    operations: [],
  });
  const result = filter({
    type: 'exception',
    meta: {
      user: { name: 'PRIVATE_DEVICE_NAME' },
      page: { url: 'https://zentral.example.test/public/mdm/family-setup/?private=query#token=SECRET_CAPABILITY' },
      sdk: { name: 'test', version: '1' },
      session: { id: 'opaque', attributes: { isSampled: 'true' } },
    },
    payload: { type: 'Error', value: 'PRIVATE_DEVICE_NAME SECRET_CAPABILITY', timestamp: new Date().toISOString() },
  });
  assert.equal(result.meta.page.url, '/public/mdm/family-setup/');
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|SECRET|private=query|token=/);
});
