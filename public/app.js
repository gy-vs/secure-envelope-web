import {
  batchItems,
  createViewGuard,
  keyRef,
  rotationStatusLabel,
  statusLabel,
  summarizeItems,
} from '/review-view.mjs';

// The page keeps no result arrays of its own. Selection state is only "which
// rotation / batch is being viewed"; every render is driven by a fresh server
// response, and the guard discards responses that arrive out of order.
const selection = {rotationId: null, batchSeq: null};
const guard = createViewGuard();

const $ = selector => document.querySelector(selector);

function notice(text, isError = false) {
  const node = $('#notice');
  node.textContent = text;
  node.className = isError ? 'error' : '';
}

async function api(path, options = {}) {
  const response = await fetch(path, options.method ? {
    ...options,
    headers: {'content-type': 'application/json'},
    body: options.body ? JSON.stringify(options.body) : undefined,
  } : options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error ?? `请求失败 (${response.status})`);
  return payload;
}

async function run(action) {
  try {
    await action();
  } catch (error) {
    notice(error.message, true);
  }
  await refresh();
}

async function refresh() {
  const token = guard.next();
  const view = await api('/api/keyring');
  let rotation = null;
  if (selection.rotationId !== null) {
    rotation = await api(`/api/rotations/${selection.rotationId}`).catch(() => null);
    if (!rotation) selection.rotationId = null;
  }
  if (!guard.isCurrent(token)) return; // a newer request superseded this one
  renderKeys(view.keys);
  renderEnvelopes(view.envelopes, view.keys);
  renderRotations(view.rotations);
  renderDetail(rotation);
}

function badge(status, label = statusLabel(status)) {
  const span = document.createElement('span');
  span.className = `badge ${status}`;
  span.textContent = label;
  return span;
}

function cell(row, content) {
  const td = row.insertCell();
  if (content instanceof Node) td.append(content);
  else td.textContent = content ?? '';
  return td;
}

function actionButton(label, onClick) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.onclick = onClick;
  return button;
}

function renderKeys(keys) {
  const tbody = $('#keys-table tbody');
  tbody.replaceChildren();
  const select = $('#envelope-key');
  select.replaceChildren();
  for (const key of keys) {
    const row = tbody.insertRow();
    cell(row, key.id);
    cell(row, `v${key.currentVersion}`);
    cell(row, key.versions.map(version =>
      `v${version.version}（${version.status === 'active' ? '启用' : '停用'} / ${version.fingerprint}）`).join('　'));
    const actions = cell(row, '');
    actions.append(actionButton('新增版本', () => run(() => api(`/api/keys/${encodeURIComponent(key.id)}/versions`, {method: 'POST'}))));
    for (const version of key.versions) {
      const next = version.status === 'active' ? 'disabled' : 'active';
      const label = version.status === 'active' ? `停用 v${version.version}` : `启用 v${version.version}`;
      actions.append(actionButton(label, () => run(() =>
        api(`/api/keys/${encodeURIComponent(key.id)}/versions/${version.version}/status`, {method: 'POST', body: {status: next}}))));
    }
    const option = document.createElement('option');
    option.value = key.id;
    option.textContent = `${key.id}（当前 v${key.currentVersion}）`;
    select.append(option);
  }
}

function renderEnvelopes(envelopes) {
  const tbody = $('#envelopes-table tbody');
  tbody.replaceChildren();
  for (const envelope of envelopes) {
    const row = tbody.insertRow();
    cell(row, envelope.id);
    cell(row, envelope.digest);
    cell(row, keyRef(envelope.keyId, envelope.keyVersion));
    const history = envelope.wraps
      .map(wrap => `#${wrap.seq} ${keyRef(wrap.keyId, wrap.keyVersion)} ${wrap.state}${wrap.rotationId ? `（轮换 ${wrap.rotationId}）` : ''} ${wrap.fingerprint}`)
      .join('\n');
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = `${envelope.wraps.length} 个版本`;
    const pre = document.createElement('pre');
    pre.textContent = history;
    details.append(summary, pre);
    cell(row, details);
    cell(row, actionButton('解密', () => run(async () => {
      const result = await api(`/api/envelopes/${encodeURIComponent(envelope.id)}/decrypt`, {method: 'POST'});
      $('#decrypt-result').innerHTML = '';
      const p = document.createElement('p');
      p.textContent = `信封 ${result.id} 使用 ${keyRef(result.keyId, result.keyVersion)} 解包，数据密钥摘要 ${result.dataKeyDigest}`;
      $('#decrypt-result').append(p);
    })));
  }
}

function renderRotations(rotations) {
  const tbody = $('#rotations-table tbody');
  tbody.replaceChildren();
  for (const rotation of rotations) {
    const row = tbody.insertRow();
    cell(row, `轮换 ${rotation.id}`);
    cell(row, keyRef(rotation.from.keyId, rotation.from.version));
    cell(row, keyRef(rotation.to.keyId, rotation.to.version));
    cell(row, badge(rotation.status, rotationStatusLabel(rotation.status)));
    const counts = summarizeItems(rotation.items);
    cell(row, `成功 ${counts.succeeded} / 共 ${rotation.items.length}`);
    cell(row, actionButton('审阅', () => {
      selection.rotationId = rotation.id;
      selection.batchSeq = null;
      void refresh();
    }));
  }
}

function renderDetail(rotation) {
  const section = $('#rotation-detail');
  if (!rotation) {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  $('#detail-title').textContent = `#${rotation.id}（${keyRef(rotation.from.keyId, rotation.from.version)} → ${keyRef(rotation.to.keyId, rotation.to.version)}）`;
  const status = $('#detail-status');
  status.replaceChildren(badge(rotation.status, rotationStatusLabel(rotation.status)));
  $('#policy-max-attempts').value = rotation.policy.maxAttempts;

  if (selection.batchSeq === null || !rotation.batches.some(batch => batch.seq === selection.batchSeq)) {
    selection.batchSeq = rotation.batches[0]?.seq ?? null;
  }
  const tabs = $('#batches');
  tabs.replaceChildren();
  for (const batch of rotation.batches) {
    const counts = batch.counts;
    const label = `批次 ${batch.seq}（待 ${counts.pending} / 成 ${counts.succeeded} / 败 ${counts.failed} / 确认 ${counts.needs_confirmation}）`;
    const tab = actionButton(label, () => {
      selection.batchSeq = batch.seq;
      void refresh(); // switching batches always re-fetches from the server
    });
    if (batch.seq === selection.batchSeq) tab.classList.add('active');
    tabs.append(tab);
    tabs.append(actionButton(`运行批次 ${batch.seq}`, () => run(() =>
      api(`/api/rotations/${rotation.id}/batches/${batch.seq}/run`, {method: 'POST'}))));
  }

  const tbody = $('#items-table tbody');
  tbody.replaceChildren();
  const items = batchItems(rotation, selection.batchSeq);
  const historyLines = [];
  for (const item of items) {
    const row = tbody.insertRow();
    cell(row, item.envelopeId);
    cell(row, badge(item.status));
    cell(row, `${item.attempts} / ${rotation.policy.maxAttempts}`);
    const errorCell = cell(row, '');
    if (item.lastError) {
      const span = document.createElement('span');
      span.className = 'error';
      span.textContent = `${item.errorClass}: ${item.lastError}`;
      errorCell.append(span);
    }
    const actions = cell(row, '');
    if (item.actions.retry) {
      actions.append(actionButton('重试', () => run(() =>
        api(`/api/rotations/${rotation.id}/items/${encodeURIComponent(item.envelopeId)}/retry`, {method: 'POST'}))));
    }
    if (item.actions.confirm) {
      actions.append(actionButton('人工确认', () => run(async () => {
        const note = window.prompt('确认说明（将记入审计记录）', '人工确认继续');
        if (note === null) return;
        await api(`/api/rotations/${rotation.id}/items/${encodeURIComponent(item.envelopeId)}/confirm`, {method: 'POST', body: {note}});
      })));
    }
    for (const entry of item.history) {
      historyLines.push(`${item.envelopeId} #${entry.seq} ${entry.from ?? '∅'} → ${entry.to} 来源 ${entry.source}${entry.reason ? `（${entry.reason}）` : ''}`);
    }
  }
  $('#item-history').textContent = historyLines.join('\n');
}

$('#key-form').onsubmit = event => {
  event.preventDefault();
  run(() => api('/api/keys', {method: 'POST', body: {keyId: $('#key-id').value.trim()}}));
};

$('#envelope-form').onsubmit = event => {
  event.preventDefault();
  run(() => api('/api/envelopes', {method: 'POST', body: {
    id: $('#envelope-id').value.trim(),
    keyId: $('#envelope-key').value,
    digest: $('#envelope-digest').value.trim(),
  }}));
};

$('#rotation-form').onsubmit = event => {
  event.preventDefault();
  run(async () => {
    const rotation = await api('/api/rotations', {method: 'POST', body: {
      from: $('#rotation-from').value.trim(),
      to: $('#rotation-to').value.trim(),
      batchSize: Number($('#rotation-batch-size').value),
      maxAttempts: Number($('#rotation-max-attempts').value),
    }});
    selection.rotationId = rotation.id;
    selection.batchSeq = null;
  });
};

$('#policy-save').onclick = () => run(() =>
  api(`/api/rotations/${selection.rotationId}/policy`, {method: 'PATCH', body: {maxAttempts: Number($('#policy-max-attempts').value)}}));

void refresh();
