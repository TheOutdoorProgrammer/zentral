import { initializeTelemetry } from '@nerdswhofish/browser-telemetry';

const config = document.getElementById('telemetry-config');
if (config) {
  const { url, version, environment } = JSON.parse(config.textContent);
  initializeTelemetry({
    url,
    app: { name: 'zentral', version, environment },
    routes: ['/', '/accounts/login/', '/accounts/logout/', '/accounts/oidc/login/', '/accounts/oidc/callback/'],
    assets: ['/static/dist/telemetry.js', '/static/dist/main.js', '/static/dist/theme.js'],
    operations: [],
  });
}
