// Pure view logic for the rotation review page. The browser never infers
// completion from local arrays or clocks: every status shown here comes from
// a server response, and the view guard drops responses that arrive after a
// newer request was issued (e.g. when the user switches batches quickly).

export const STATUS_LABELS = {
  pending: '待处理',
  processing: '进行中',
  succeeded: '成功',
  failed: '失败',
  needs_confirmation: '需要人工确认',
};

export const ROTATION_STATUS_LABELS = {
  pending: '待处理',
  running: '进行中',
  completed: '已完成',
  attention_required: '需要处理',
};

export function statusLabel(status) {
  return STATUS_LABELS[status] ?? status;
}

export function rotationStatusLabel(status) {
  return ROTATION_STATUS_LABELS[status] ?? status;
}

export function keyRef(keyId, version) {
  return `${keyId}@${version}`;
}

export function summarizeItems(items) {
  const counts = {pending: 0, processing: 0, succeeded: 0, failed: 0, needs_confirmation: 0};
  for (const item of items ?? []) {
    if (item.status in counts) counts[item.status] += 1;
  }
  return counts;
}

// Items of one batch, taken from the rotation payload that was just fetched
// from the server — never from a cached copy of another batch.
export function batchItems(rotation, batchSeq) {
  const batch = (rotation?.batches ?? []).find(entry => entry.seq === batchSeq);
  if (!batch) return [];
  return (rotation.items ?? []).filter(item => batch.itemIds.includes(item.id));
}

// Monotonic request guard: only the most recently issued request may update
// the page, so a slow earlier response cannot overwrite fresher state.
export function createViewGuard() {
  let latest = 0;
  return {
    next() {
      latest += 1;
      return latest;
    },
    isCurrent(token) {
      return token === latest;
    },
  };
}
