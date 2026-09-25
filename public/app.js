// Pure view-state functions. The browser keeps no local task list: every render
// derives from the latest server snapshot. Snapshots carry the server's
// monotonic `seq`, so an out-of-order or replayed response can never overwrite a
// newer view — old task results are never shown as the current state.
export function createViewState() {
  return {seq: 0, snapshot: null, selectedRotationId: null};
}

export function applySnapshot(view, snapshot) {
  if (!snapshot || typeof snapshot.seq !== 'number') return view;
  if (view.snapshot && snapshot.seq < view.snapshot.seq) return view;
  return {...view, seq: snapshot.seq, snapshot};
}

export function selectRotation(view, rotationId) {
  return {...view, selectedRotationId: rotationId};
}

export function currentRotation(view) {
  if (!view.snapshot || view.selectedRotationId == null) return null;
  return view.snapshot.rotations.find(rotation => rotation.id === view.selectedRotationId) ?? null;
}

export function rotationItems(view) {
  return currentRotation(view)?.items ?? [];
}

export const STATUS_LABELS = {
  pending: 'pending',
  in_progress: 'in progress',
  succeeded: 'succeeded',
  failed: 'failed',
  needs_review: 'needs review',
  skipped: 'skipped',
};

if (typeof document !== 'undefined') {
  bootstrap();
}

function bootstrap() {
  let view = createViewState();
  const $ = selector => document.querySelector(selector);

  async function request(path, options) {
    const response = await fetch(path, options);
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error ?? `request failed: ${response.status}`);
    return payload;
  }

  function post(path, body) {
    return request(path, {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body ?? {})});
  }

  async function refresh() {
    view = applySnapshot(view, await request('/api/keyring'));
    render();
  }

  async function run(action) {
    $('#error').textContent = '';
    try {
      const result = await action();
      await refresh();
      return result;
    } catch (error) {
      $('#error').textContent = error.message;
      return null;
    }
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function badge(status) {
    const span = document.createElement('span');
    span.className = 'badge';
    span.dataset.status = status;
    span.textContent = STATUS_LABELS[status] ?? status;
    return span;
  }

  function cell(row, text) {
    const td = document.createElement('td');
    td.textContent = text ?? '';
    return td;
  }

  function button(text, handler) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = text;
    btn.addEventListener('click', handler);
    return btn;
  }

  function renderKeys(snapshot) {
    const body = $('#keys-body');
    clear(body);
    for (const key of snapshot.keys) {
      const row = document.createElement('tr');
      row.append(cell(row, key.version), cell(row, key.status), cell(row, key.createdSeq));
      const actionCell = document.createElement('td');
      actionCell.append(button(key.status === 'active' ? 'Disable' : 'Activate', () => {
        void run(() => post(`/api/keys/${encodeURIComponent(key.version)}/status`, {status: key.status === 'active' ? 'disabled' : 'active'}));
      }));
      row.append(actionCell);
      body.append(row);
    }
  }

  function renderEnvelopes(snapshot) {
    const body = $('#envelopes-body');
    clear(body);
    for (const envelope of snapshot.envelopes) {
      const row = document.createElement('tr');
      row.append(cell(row, envelope.id), cell(row, envelope.keyId));
      const wrapsCell = document.createElement('td');
      for (const wrap of envelope.wraps) {
        const line = document.createElement('div');
        line.textContent = `wrap #${wrap.wrapId}: data key under ${wrap.keyVersion} (${wrap.state}${wrap.rotationId ? `, rotation #${wrap.rotationId}` : ''})`;
        wrapsCell.append(line);
      }
      row.append(wrapsCell);
      body.append(row);
    }
  }

  function renderRotations(snapshot) {
    const body = $('#rotations-body');
    clear(body);
    for (const rotation of snapshot.rotations) {
      const row = document.createElement('tr');
      if (rotation.id === view.selectedRotationId) row.classList.add('selected');
      row.append(cell(row, rotation.id), cell(row, `${rotation.from} → ${rotation.to}`));
      const statusCell = document.createElement('td');
      statusCell.append(badge(rotation.status));
      row.append(statusCell);
      row.append(cell(row, JSON.stringify(rotation.counts)));
      row.addEventListener('click', () => {
        // Switching batches renders from the current snapshot and immediately
        // re-fetches; stale responses are rejected by applySnapshot.
        view = selectRotation(view, rotation.id);
        render();
        void refresh();
      });
      body.append(row);
    }
  }

  function renderItems() {
    const body = $('#items-body');
    clear(body);
    const rotation = currentRotation(view);
    if (!rotation) {
      $('#rotation-title').textContent = 'No rotation selected';
      return;
    }
    $('#rotation-title').textContent = `Rotation #${rotation.id}: ${rotation.from} → ${rotation.to}`;
    for (const item of rotation.items) {
      const row = document.createElement('tr');
      row.append(cell(row, item.envelopeId));
      const statusCell = document.createElement('td');
      statusCell.append(badge(item.status));
      row.append(statusCell);
      row.append(cell(row, item.attempts), cell(row, item.failureReason), cell(row, item.updatedSeq));
      const actionCell = document.createElement('td');
      if (item.status === 'failed') {
        actionCell.append(button('Retry', () => {
          void run(() => post(`/api/rotations/${rotation.id}/retry`, {envelopeIds: [item.envelopeId]}));
        }));
      }
      if (item.status === 'needs_review') {
        actionCell.append(button('Confirm & retry', () => {
          void run(() => post(`/api/rotations/${rotation.id}/items/${encodeURIComponent(item.envelopeId)}`, {action: 'retry'}));
        }));
        actionCell.append(button('Confirm skip', () => {
          void run(() => post(`/api/rotations/${rotation.id}/items/${encodeURIComponent(item.envelopeId)}`, {action: 'skip'}));
        }));
      }
      row.append(actionCell);
      body.append(row);
    }
  }

  function renderEvents(snapshot) {
    const body = $('#events-body');
    clear(body);
    for (const event of snapshot.events.slice(-15).reverse()) {
      const {seq, type, ...detail} = event;
      const row = document.createElement('tr');
      row.append(cell(row, seq), cell(row, type), cell(row, JSON.stringify(detail)));
      body.append(row);
    }
  }

  function render() {
    const snapshot = view.snapshot;
    if (!snapshot) return; // nothing local to show until the server answers
    fillKeySelects($('#envelope-key'));
    fillKeySelects($('#rotation-from'));
    fillKeySelects($('#rotation-to'));
    renderKeys(snapshot);
    renderEnvelopes(snapshot);
    renderRotations(snapshot);
    renderItems();
    renderEvents(snapshot);
  }

  function fillKeySelects(select) {
    if (!select) return;
    const value = select.value;
    clear(select);
    const snapshot = view.snapshot;
    if (snapshot) {
      for (const key of snapshot.keys) {
        const option = document.createElement('option');
        option.value = key.version;
        option.textContent = `${key.version} (${key.status})`;
        select.append(option);
      }
    }
    if (value && snapshot.keys.some(key => key.version === value)) select.value = value;
  }

  function selectedRotation() {
    return currentRotation(view)?.id ?? null;
  }

  $('#key-form').addEventListener('submit', event => {
    event.preventDefault();
    const input = $('#key-id');
    void run(() => post('/api/keys', {keyId: input.value})).then(() => { input.value = ''; });
  });

  $('#envelope-form').addEventListener('submit', event => {
    event.preventDefault();
    const id = $('#envelope-id');
    const digest = $('#envelope-digest');
    const keyId = $('#envelope-key').value;
    void run(() => post('/api/envelopes', {id: id.value, keyId, digest: digest.value})).then(() => { id.value = ''; digest.value = ''; });
  });

  $('#open-form').addEventListener('submit', event => {
    event.preventDefault();
    const id = $('#open-id');
    const version = $('#open-version').value.trim();
    void run(async () => {
      const result = await post(`/api/envelopes/${encodeURIComponent(id.value)}/open`, version ? {keyVersion: version} : {});
      $('#open-result').textContent = `${result.id} opened with key version ${result.keyVersion}: ${result.digest}`;
      return result;
    });
  });

  $('#rotation-form').addEventListener('submit', event => {
    event.preventDefault();
    void run(() => post('/api/rotations', {from: $('#rotation-from').value, to: $('#rotation-to').value})).then(rotation => {
      if (rotation) {
        view = selectRotation(view, rotation.id);
        render();
      }
    });
  });

  $('#process-batch').addEventListener('click', () => {
    const id = selectedRotation();
    if (id == null) { $('#error').textContent = 'select a rotation first'; return; }
    const batchSize = Number($('#batch-size').value) || 1;
    void run(() => post(`/api/rotations/${id}/process`, {batchSize}));
  });

  $('#commit-batch').addEventListener('click', () => {
    const id = selectedRotation();
    if (id == null) { $('#error').textContent = 'select a rotation first'; return; }
    void run(() => post(`/api/rotations/${id}/commit`, {}));
  });

  $('#retry-failed').addEventListener('click', () => {
    const id = selectedRotation();
    if (id == null) { $('#error').textContent = 'select a rotation first'; return; }
    void run(() => post(`/api/rotations/${id}/retry`, {}));
  });

  void refresh();
}
