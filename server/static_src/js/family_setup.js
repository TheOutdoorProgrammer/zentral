import '../scss/family_setup.scss';

/* The fragment is a credential. Remove it before parsing config or loading telemetry. */
let activationToken = new URLSearchParams(window.location.hash.slice(1)).get('token');
if (window.location.hash) {
  window.history.replaceState(null, '', window.location.pathname + window.location.search);
}

const root = document.getElementById('family-setup');
const announcement = document.getElementById('setup-announcement');
const config = JSON.parse(document.getElementById('family-setup-config').textContent);
const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
let state = null;
let busy = false;
let errorMessage = '';
let lastLoaded = null;
let openSteps = new Set();

if (config.telemetry_script_url && document.getElementById('telemetry-config')) {
  const scriptURL = new URL(config.telemetry_script_url, window.location.origin);
  if (scriptURL.origin === window.location.origin) {
    const script = document.createElement('script');
    script.src = scriptURL.href;
    document.head.append(script);
  }
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function announce(message) {
  announcement.textContent = message;
}

function button(label, action, className = 'button', focusKey) {
  const node = element('button', className, label);
  node.type = 'button';
  node.disabled = busy;
  if (focusKey) node.dataset.focusKey = focusKey;
  node.addEventListener('click', action);
  return node;
}

function dateLabel(value) {
  if (!value) return 'Not yet reported';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Report time unavailable';
  return date.toLocaleString(undefined, {month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'});
}

function safeLink(label, url) {
  try {
    const target = new URL(url);
    if (target.protocol !== 'https:' || target.username || target.password) return null;
    const link = element('a', 'text-link', `${label} ↗`);
    link.href = target.href;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    return link;
  } catch {
    return null;
  }
}

async function request(url, body) {
  const endpoint = new URL(url, window.location.origin);
  if (endpoint.origin !== window.location.origin) throw new Error('invalid_endpoint');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(endpoint.href, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: body === undefined ? {'Accept': 'application/json'} : {
        'Accept': 'application/json', 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    if (response.status === 401) {
      const error = new Error('pairing_required');
      error.unauthorized = true;
      throw error;
    }
    if (!response.ok) throw new Error('request_failed');
    return response.status === 204 ? null : await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

function renderUnpaired() {
  const panel = element('section', 'welcome-panel');
  panel.append(element('p', 'eyebrow', 'YOUR DEVICE FIELD GUIDE'));
  panel.append(element('h1', '', 'A place to get started.'));
  panel.append(element('p', 'intro', 'Open this device’s Family Setup icon to get your personal checklist.'));
  panel.append(element('p', 'muted', 'If it is missing or access has expired, ask a parent or the person managing this device to prepare access.'));
  panel.append(button('Try again', refresh, 'button', 'refresh'));
  return panel;
}

function renderProgress() {
  const complete = state.steps.filter(step => step.done).length;
  const total = state.steps.length;
  const allDone = total > 0 && complete === total;
  const panel = element('section', `welcome-panel${allDone ? ' is-complete' : ''}`);
  panel.append(element('p', 'eyebrow', `${state.audience === 'child' ? 'CHILD' : 'ADULT'} DEVICE · YOUR FIELD GUIDE`));
  panel.append(element('h1', '', allDone ? 'Nicely settled in.' : 'Make yourself at home.'));
  panel.append(element('p', 'intro', allDone
    ? 'Your personal checklist is complete. You can come back whenever you need a hand.'
    : 'A few things need your touch. Work through them at your own pace.'));
  const progress = element('div', 'progress-block');
  progress.append(element('p', 'progress-label', `${complete} of ${total} personal steps complete`));
  const meter = element('progress', 'progress-meter');
  meter.max = Math.max(total, 1);
  meter.value = complete;
  meter.setAttribute('aria-label', 'Personal setup progress');
  progress.append(meter);
  if (allDone) progress.append(element('p', 'completion-stamp', '✓ CHECKLIST COMPLETE'));
  else progress.append(element('p', 'progress-caption', 'Your confirmations are saved for this device.'));
  panel.append(progress);
  const jump = element('a', 'text-link steps-jump', allDone ? 'Review your steps ↓' : 'Go to your steps ↓');
  jump.href = '#steps-heading';
  panel.append(jump);
  panel.append(element('p', 'device-label', state.device_name));
  return panel;
}

function renderChecks() {
  const section = element('section', 'device-checks');
  section.setAttribute('aria-labelledby', 'checks-heading');
  const heading = element('div', 'section-heading');
  const title = element('h2', '', 'From your device');
  title.id = 'checks-heading';
  heading.append(title, button(busy ? 'Checking…' : 'Refresh', refresh, 'button button-quiet', 'refresh'));
  section.append(heading, element('p', 'section-description', 'Management reports installation here. Check the steps below to confirm things actually work.'));
  const reports = element('ul', 'report-list');
  const labels = {installed: 'Installed', pending: 'Pending', failed: 'Needs attention', not_configured: 'Not configured'};
  for (const check of state.checks) {
    const item = element('li', 'report-row');
    const text = element('div', 'report-copy');
    text.append(element('span', 'report-title', check.title), element('span', 'report-time', dateLabel(check.reported_at)));
    const status = Object.hasOwn(labels, check.status) ? check.status : 'not_configured';
    item.append(text, element('span', `report-status status-${status}`, labels[status]));
    reports.append(item);
  }
  if (!state.checks.length) reports.append(element('li', 'empty-copy', 'No installation checks have been configured yet.'));
  section.append(reports);
  section.append(element('p', 'last-seen', `Device last checked in: ${dateLabel(state.last_seen_at)}.`));
  const lastSeen = new Date(state.last_seen_at || '').getTime();
  if (!Number.isFinite(lastSeen) || Date.now() - lastSeen > 86400000) {
    section.append(element('p', 'notice notice-inline', 'Your device has not reported recently. Connect it to the internet. Installation status may be out of date.'));
  }
  return section;
}

function renderSteps() {
  const section = element('section', 'personal-steps');
  section.setAttribute('aria-labelledby', 'steps-heading');
  const title = element('h2', '', 'A few finishing touches');
  title.id = 'steps-heading';
  section.append(title, element('p', 'section-description', 'These are your confirmations. Only mark a step done after you have tried it.'));
  const list = element('ol', 'step-list');
  state.steps.forEach((step, index) => {
    const item = element('li', `step${step.done ? ' step-done' : ''}`);
    const number = element('span', 'step-number', step.done ? '✓' : String(index + 1).padStart(2, '0'));
    number.setAttribute('aria-hidden', 'true');
    item.append(number);
    const details = element('details', 'step-details');
    details.open = openSteps.has(step.id);
    details.addEventListener('toggle', () => {
      if (details.open) openSteps.add(step.id);
      else openSteps.delete(step.id);
    });
    const summary = element('summary');
    summary.dataset.focusKey = `summary-${step.id}`;
    const stepTitle = element('h3', '', step.title);
    summary.append(stepTitle, element('span', 'step-state', step.done ? 'Done' : 'View steps'));
    details.append(summary);
    const body = element('div', 'step-body');
    body.append(element('p', '', step.description));
    const instructions = element('ol', 'instructions');
    for (const instruction of step.instructions) instructions.append(element('li', '', instruction));
    if (step.instructions.length) body.append(instructions);
    if (step.link) {
      const link = safeLink(step.link.label, step.link.url);
      if (link) body.append(link);
    }
    const actions = element('div', 'step-actions');
    actions.append(button(step.done ? 'Mark as not done' : 'I’ve done this', () => updateStep(step),
      step.done ? 'button button-quiet' : 'button', `step-${step.id}`));
    body.append(actions);
    details.append(body);
    item.append(details);
    list.append(item);
  });
  if (!state.steps.length) section.append(element('p', 'empty-copy', 'There are no personal steps for this device yet.'));
  section.append(list);
  return section;
}

function renderShortcuts() {
  const section = element('section', 'shortcuts');
  section.setAttribute('aria-labelledby', 'shortcuts-heading');
  const heading = element('h2', '', 'A shorter way there');
  heading.id = 'shortcuts-heading';
  section.append(element('p', 'eyebrow', 'APPLE SHORTCUTS'), heading);
  section.append(element('p', '', 'Helpful shortcuts for this device. You choose whether to add them and approve any permissions on your device.'));
  const links = state.shortcuts.map(shortcut => safeLink(shortcut.title, shortcut.url)).filter(Boolean);
  if (links.length) {
    const list = element('ul', 'shortcut-list');
    for (const link of links) {
      const item = element('li');
      item.append(link);
      list.append(item);
    }
    section.append(list);
  } else {
    section.append(element('p', 'empty-copy', 'No shortcuts have been shared yet. They will appear here when your device manager adds them.'));
  }
  return section;
}

function render(focusKey = document.activeElement?.dataset.focusKey) {
  root.replaceChildren();
  root.setAttribute('aria-busy', String(busy));
  if (errorMessage) {
    const notice = element('div', 'notice error-notice');
    notice.append(element('p', '', errorMessage));
    if (state) notice.append(element('p', 'notice-detail', `Showing the last saved view from ${dateLabel(lastLoaded)}. Status may have changed.`));
    notice.append(button('Retry connection', refresh, 'button button-quiet', 'retry'));
    root.append(notice);
  }
  if (!state) {
    if (busy) {
      const panel = element('section', 'welcome-panel');
      panel.append(element('p', 'eyebrow', 'YOUR DEVICE FIELD GUIDE'), element('h1', '', 'Getting things ready.'), element('p', 'intro', 'Opening your setup checklist…'));
      root.append(panel);
    } else root.append(renderUnpaired());
    return;
  }
  const layout = element('div', 'setup-layout');
  const aside = element('div', 'setup-overview');
  aside.append(renderProgress(), renderChecks());
  const content = element('div', 'setup-content');
  content.append(renderSteps(), renderShortcuts());
  layout.append(aside, content);
  root.append(layout);
  const footer = element('footer', 'setup-footer');
  footer.append(element('p', '', 'This guide cannot see your passwords, app sign-ins, or browsing history.'));
  footer.append(button('Forget access on this browser', forget, 'button button-quiet', 'forget'));
  root.append(footer);
  if (focusKey) {
    const control = Array.from(root.querySelectorAll('[data-focus-key]')).find(node => node.dataset.focusKey === focusKey);
    if (control && !control.disabled) control.focus({preventScroll: true});
  }
}

async function run(action, successMessage) {
  if (busy) return;
  const focusKey = document.activeElement?.dataset.focusKey;
  busy = true;
  errorMessage = '';
  render();
  try {
    const result = await action();
    if (!state && result) {
      const nextStep = result.steps.find(step => !step.done);
      if (nextStep) openSteps.add(nextStep.id);
    }
    state = result;
    lastLoaded = new Date().toISOString();
    announce(successMessage);
  } catch (error) {
    if (error.unauthorized) {
      state = null;
      announce('Open this device’s Family Setup icon to restore access.');
    } else {
      errorMessage = 'We could not save or refresh your checklist. Check your internet connection, then try again.';
      announce(errorMessage);
    }
  } finally {
    busy = false;
    render(focusKey);
  }
}

function refresh() {
  return run(() => request(config.status_url), 'Device status refreshed.');
}

function updateStep(step) {
  return run(() => request(config.step_url, {step: step.id, done: !step.done}),
    step.done ? 'Step marked as not done.' : 'Step complete. Your progress is saved.');
}

function forget() {
  if (!window.confirm('Forget this browser’s access? Your saved checklist stays on the server. Reopen this device’s Family Setup icon to reconnect.')) return;
  return run(async () => {
    await request(config.forget_url, {});
    openSteps.clear();
    return null;
  }, 'This browser’s access has been removed.');
}

async function start() {
  if (activationToken) {
    await run(async () => {
      try {
        await request(config.activate_url, {token: activationToken});
      } finally {
        activationToken = null;
      }
      return request(config.status_url);
    }, 'Your device checklist is ready.');
  } else await refresh();
}

window.addEventListener('pageshow', event => {
  if (event.persisted) refresh();
});
start();
