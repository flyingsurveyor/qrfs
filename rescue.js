
const B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
function b45decode(s) {
  const out = [];
  for (let i = 0; i < s.length - 2; i += 3) {
    const a = B45.indexOf(s[i]);
    const b = B45.indexOf(s[i+1]);
    const c = B45.indexOf(s[i+2]);
    if (a < 0 || b < 0 || c < 0) throw new Error('invalid base45');
    const val = a + b * 45 + c * 2025;
    out.push(val >> 8, val & 0xFF);
  }
  if (s.length % 3 === 2) {
    const a = B45.indexOf(s[s.length-2]);
    const b = B45.indexOf(s[s.length-1]);
    if (a < 0 || b < 0) throw new Error('invalid base45');
    out.push(a + b * 45);
  } else if (s.length % 3 === 1) {
    throw new Error('invalid base45 length');
  }
  return new Uint8Array(out);
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function parseChunkHeader(bytes) {
  const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
  const view = new DataView(bytes.buffer, bytes.byteOffset);
  const fileIdHex = bytes.length >= 21 ? bytesToHex(bytes.slice(5, 21)) : null;
  if (magic === 'QRC1') {
    if (bytes.length < 31) return null;
    const index = view.getUint32(21);
    const total = view.getUint32(25);
    return { magic, fileIdHex, index, total, kind: 0, fecType: 0, groupIndex: 0, groupSize: 0, parityCount: 0, parityIndex: 0, uniqueKey: `d:${index}` };
  }
  if (magic === 'QRC2') {
    if (bytes.length < 38) return null;
    const kind = view.getUint8(21);
    const index = view.getUint32(22);
    const total = view.getUint32(26);
    const groupIndex = view.getUint32(32);
    const groupSize = view.getUint16(36);
    return { magic, fileIdHex, index, total, kind, fecType: kind === 1 ? 1 : 0, groupIndex, groupSize, parityCount: kind === 1 ? 1 : 0, parityIndex: 0, uniqueKey: kind === 1 ? `p:${groupIndex}:0` : `d:${index}` };
  }
  if (magic === 'QRC3') {
    if (bytes.length < 43) return null;
    const kind = view.getUint8(21);
    const fecType = view.getUint8(22);
    const index = view.getUint32(23);
    const total = view.getUint32(27);
    const groupIndex = view.getUint32(33);
    const groupSize = view.getUint16(37);
    const parityCount = view.getUint16(39);
    const parityIndex = view.getUint16(41);
    return { magic, fileIdHex, index, total, kind, fecType, groupIndex, groupSize, parityCount, parityIndex, uniqueKey: kind === 1 ? `p:${groupIndex}:${parityIndex}` : `d:${index}` };
  }
  return null;
}
function fecLabel(header) {
  if (!header || header.kind !== 1) return '';
  if (header.magic === 'QRC2' || header.fecType === 1) return 'XOR';
  if (header.fecType === 2) return 'RS';
  return `FEC-${header.fecType}`;
}
function describeHeader(header) {
  if (!header) return 'Unknown chunk';
  if (header.kind === 0) return `Data chunk ${header.index + 1}/${header.total}`;
  const groupLabel = header.groupIndex + 1;
  const parityLabel = header.parityCount > 1 ? `parity ${header.parityIndex + 1}/${header.parityCount}` : 'parity';
  return `${fecLabel(header)} ${parityLabel} for group ${groupLabel}`;
}
function missingChunkSummary() {
  if (!totalChunks) return 'Missing data chunks will appear here after the first valid QRFS chunk.';
  const missing = [];
  for (let i = 0; i < totalChunks; i++) {
    if (!dataSeen[i]) missing.push(i + 1);
  }
  if (!missing.length) return 'All data chunks collected.';
  const preview = missing.slice(0, 24).join(', ');
  const suffix = missing.length > 24 ? ` … (+${missing.length - 24} more)` : '';
  return `Missing data chunks (${missing.length}): ${preview}${suffix}`;
}
let scanner = null;
let chunkMap = {};
let chunkHeaders = {};
let dataSeen = {};
let totalChunks = 0;
let activeFileId = null;
let lastBeep = 0;
let currentCapabilities = {};
let currentSettings = {};
const progressText = document.getElementById('progress-text');
const progressWrap = document.getElementById('progress-bar-wrap');
const progressBar = document.getElementById('progress-bar');
const chunkGrid = document.getElementById('chunk-grid');
const chunkInput = document.getElementById('chunk-data-input');
const lastRead = document.getElementById('last-read');
const missingChunks = document.getElementById('missing-chunks');
const manualFeedback = document.getElementById('manual-feedback');
const manualInput = document.getElementById('manual-chunk-input');
function beep() {
  const now = Date.now();
  if (now - lastBeep < 300) return;
  lastBeep = now;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    osc.type = 'sine';
    osc.frequency.value = 1200;
    osc.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.08);
  } catch (e) {}
}
function denseModeEnabled() { return document.getElementById('dense-mode')?.checked; }
function updateCameraDiag(extra='') {
  const diag = document.getElementById('camera-diag');
  const parts = [];
  if (currentSettings.width && currentSettings.height) parts.push(`Resolution: ${currentSettings.width}×${currentSettings.height}`);
  if (currentSettings.frameRate) parts.push(`FPS: ${Math.round(currentSettings.frameRate * 10) / 10}`);
  if (typeof currentSettings.zoom !== 'undefined') parts.push(`Zoom: ${Number(currentSettings.zoom).toFixed(1)}`);
  if (currentSettings.focusMode) parts.push(`Focus: ${currentSettings.focusMode}`);
  if (extra) parts.push(extra);
  diag.textContent = parts.length ? parts.join(' · ') : 'No camera started.';
}
function updateUI() {
  const foundData = Object.keys(dataSeen).length;
  const foundUnique = Object.keys(chunkMap).length;
  chunkInput.value = JSON.stringify(Object.values(chunkMap));
  if (totalChunks > 0) {
    progressWrap.style.display = '';
    progressBar.style.width = `${Math.max(1, Math.min(100, (foundData / totalChunks) * 100))}%`;
    progressBar.style.background = foundData === totalChunks ? '#2e7d32' : '#2f6fed';
  } else {
    progressWrap.style.display = foundUnique ? '' : 'none';
    progressBar.style.width = foundUnique ? '12%' : '0%';
    progressBar.style.background = '#2f6fed';
  }
  chunkGrid.innerHTML = '';
  if (totalChunks > 0) {
    for (let i = 0; i < totalChunks; i++) {
      const box = document.createElement('div');
      box.style.cssText = 'width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:bold;';
      if (dataSeen[i]) {
        box.style.background = '#2f6fed';
        box.style.color = '#fff';
      } else {
        box.style.background = '#dde4ef';
        box.style.color = '#6c7a90';
      }
      box.textContent = i + 1;
      chunkGrid.appendChild(box);
    }
  } else {
    Object.values(chunkHeaders).forEach((header) => {
      const dot = document.createElement('span');
      dot.className = 'badge neutral';
      dot.textContent = header.kind === 0 ? 'D' : 'P';
      chunkGrid.appendChild(dot);
    });
  }
  const parityCount = Math.max(0, foundUnique - foundData);
  if (totalChunks > 0) {
    progressText.textContent = parityCount > 0
      ? `Data collected: ${foundData}/${totalChunks} · extra parity: ${parityCount}`
      : `Data collected: ${foundData}/${totalChunks}`;
  } else if (foundUnique > 0) {
    progressText.textContent = `Collected ${foundUnique} valid chunks. Keep adding material or run rescue.`;
  } else {
    progressText.textContent = 'Ready. Start the camera or add manual chunks.';
  }
  missingChunks.textContent = missingChunkSummary();
  const btn = document.getElementById('btn-submit');
  const hint = document.getElementById('submit-hint');
  btn.disabled = foundUnique === 0;
  if (totalChunks > 0 && foundData === totalChunks) {
    hint.textContent = parityCount > 0
      ? `All data chunks collected. Extra parity stored: ${parityCount}.`
      : 'All data chunks collected.';
    hint.style.color = '#2e7d32';
  } else if (foundUnique > 0) {
    hint.textContent = `${Math.max(0, totalChunks - foundData)} data chunks still missing. You can still try reconstruction: FEC may recover them if enough parity was collected.`;
    hint.style.color = '';
  } else {
    hint.textContent = 'Add any combination of chunks, then run the mixed recovery.';
    hint.style.color = '';
  }
}
function resetCollectedChunks(message='Collected rescue state cleared.') {
  chunkMap = {};
  chunkHeaders = {};
  dataSeen = {};
  totalChunks = 0;
  activeFileId = null;
  chunkInput.value = '[]';
  lastRead.textContent = 'No chunk collected yet.';
  manualFeedback.textContent = message;
  updateUI();
}
function addChunkText(decodedText, sourceLabel='chunk') {
  const normalized = (decodedText || '').trim();
  if (!normalized) return { status: 'empty', message: 'Empty chunk ignored.' };
  let bytes;
  try {
    bytes = b45decode(normalized);
  } catch (e) {
    return { status: 'invalid', message: `Invalid Base45 from ${sourceLabel}.` };
  }
  const header = parseChunkHeader(bytes);
  if (!header) {
    return { status: 'invalid', message: `The ${sourceLabel} is not a valid QRFS chunk.` };
  }
  if (activeFileId && header.fileIdHex && header.fileIdHex !== activeFileId) {
    return { status: 'foreign', message: `Rejected ${sourceLabel}: it belongs to another file.` };
  }
  if (totalChunks && header.total && header.total !== totalChunks) {
    return { status: 'invalid', message: `Rejected ${sourceLabel}: total chunk count mismatch (${header.total} vs ${totalChunks}).` };
  }
  if (chunkMap[header.uniqueKey] !== undefined) {
    return { status: 'duplicate', message: `${describeHeader(header)} already collected.` };
  }
  activeFileId = activeFileId || header.fileIdHex || null;
  chunkMap[header.uniqueKey] = normalized;
  chunkHeaders[header.uniqueKey] = header;
  if (header.kind === 0) dataSeen[header.index] = true;
  totalChunks = Math.max(totalChunks, header.total || 0);
  lastRead.textContent = `Last accepted from ${sourceLabel}: ${describeHeader(header)}${header.fileIdHex ? ` · file ${header.fileIdHex.slice(0, 12)}…` : ''}`;
  updateUI();
  return { status: 'added', header, message: `${describeHeader(header)} accepted.` };
}
function onScanSuccess(decodedText) {
  const result = addChunkText(decodedText, 'camera');
  if (result.status !== 'added') return;
  beep();
  if (manualFeedback) manualFeedback.textContent = result.message;
  if (totalChunks > 0 && Object.keys(dataSeen).length === totalChunks && scanner) {
    setTimeout(() => {
      stopScanner();
      progressText.textContent = `Done. All ${totalChunks} data chunks collected.`;
    }, 500);
  }
}
function addManualChunksFromInput() {
  const raw = manualInput?.value || '';
  const lines = raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (!lines.length) {
    manualFeedback.textContent = 'Paste at least one Base45 chunk first.';
    return;
  }
  let added = 0;
  let duplicate = 0;
  let rejected = 0;
  let lastMessage = '';
  for (const line of lines) {
    const result = addChunkText(line, 'manual input');
    lastMessage = result.message;
    if (result.status === 'added') added += 1;
    else if (result.status === 'duplicate') duplicate += 1;
    else if (result.status !== 'empty') rejected += 1;
  }
  if (added > 0) beep();
  if (manualInput) manualInput.value = '';
  const parts = [];
  if (added) parts.push(`${added} added`);
  if (duplicate) parts.push(`${duplicate} duplicate`);
  if (rejected) parts.push(`${rejected} rejected`);
  manualFeedback.textContent = parts.length ? `Manual input processed: ${parts.join(' · ')}. ${lastMessage}` : lastMessage;
}
function baseConfig() {
  const dense = denseModeEnabled();
  const formats = (window.Html5QrcodeSupportedFormats && Array.isArray(window.Html5QrcodeSupportedFormats)) ? [window.Html5QrcodeSupportedFormats.QR_CODE] : undefined;
  return {
    fps: dense ? 6 : 8,
    aspectRatio: 4/3,
    disableFlip: true,
    qrbox: (w, h) => { const edge = Math.floor(Math.min(w, h) * (dense ? 0.86 : 0.72)); return { width: edge, height: edge }; },
    formatsToSupport: formats,
  };
}
async function chooseRearCameraId() {
  if (!window.Html5Qrcode || !Html5Qrcode.getCameras) return null;
  try {
    const devices = await Html5Qrcode.getCameras();
    if (!devices || !devices.length) return null;
    const labeled = devices.find(d => /back|rear|environment/i.test(d.label || ''));
    return (labeled || devices[0]).id;
  } catch (e) { return null; }
}
async function applyBestEffortConstraints() {
  if (!scanner) return;
  try {
    if (typeof scanner.getRunningTrackSettings === 'function') currentSettings = scanner.getRunningTrackSettings() || {};
    if (typeof scanner.getRunningTrackCapabilities === 'function') currentCapabilities = scanner.getRunningTrackCapabilities() || {};
  } catch (e) { currentCapabilities = {}; }
  const caps = currentCapabilities || {};
  const advanced = [];
  if (Array.isArray(caps.focusMode) && caps.focusMode.includes('continuous')) advanced.push({ focusMode: 'continuous' });
  if (caps.zoom && typeof caps.zoom.max !== 'undefined' && caps.zoom.max > 1) advanced.push({ zoom: Math.min(denseModeEnabled() ? 2 : 1.4, caps.zoom.max) });
  const constraints = {
    width: { ideal: denseModeEnabled() ? 1920 : 1280 },
    height: { ideal: denseModeEnabled() ? 1440 : 960 },
    frameRate: { ideal: denseModeEnabled() ? 6 : 8, max: denseModeEnabled() ? 10 : 12 },
    advanced,
  };
  try { if (typeof scanner.applyVideoConstraints === 'function') await scanner.applyVideoConstraints(constraints); } catch (e) {}
  try {
    if (typeof scanner.getRunningTrackSettings === 'function') currentSettings = scanner.getRunningTrackSettings() || currentSettings;
    if (typeof scanner.getRunningTrackCapabilities === 'function') currentCapabilities = scanner.getRunningTrackCapabilities() || currentCapabilities;
  } catch (e) {}
  setupCameraControls();
  updateCameraDiag(denseModeEnabled() ? 'Profile: dense' : 'Profile: standard');
}
function setupCameraControls() {
  const controls = document.getElementById('camera-controls');
  const zoomWrap = document.getElementById('zoom-wrap');
  const torchWrap = document.getElementById('torch-wrap');
  const zoomSlider = document.getElementById('zoom-slider');
  const torchToggle = document.getElementById('torch-toggle');
  controls.style.display = 'block';
  const caps = currentCapabilities || {};
  if (caps.zoom && typeof caps.zoom.max !== 'undefined' && caps.zoom.max > (caps.zoom.min || 1)) {
    zoomWrap.style.display = '';
    zoomSlider.min = caps.zoom.min || 1;
    zoomSlider.max = caps.zoom.max;
    zoomSlider.step = caps.zoom.step || 0.1;
    zoomSlider.value = currentSettings.zoom || zoomSlider.min;
    zoomSlider.oninput = async () => {
      if (!scanner || typeof scanner.applyVideoConstraints !== 'function') return;
      try {
        await scanner.applyVideoConstraints({ advanced: [{ zoom: Number(zoomSlider.value) }] });
        currentSettings.zoom = Number(zoomSlider.value);
        updateCameraDiag(denseModeEnabled() ? 'Profile: dense' : 'Profile: standard');
      } catch (e) {}
    };
  } else zoomWrap.style.display = 'none';
  if (Array.isArray(caps.torch) ? caps.torch.includes(true) : !!caps.torch) {
    torchWrap.style.display = '';
    torchToggle.onchange = async () => {
      if (!scanner || typeof scanner.applyVideoConstraints !== 'function') return;
      try { await scanner.applyVideoConstraints({ advanced: [{ torch: !!torchToggle.checked }] }); } catch (e) {}
    };
  } else torchWrap.style.display = 'none';
}
async function startScanner() {
  document.getElementById('btn-start').style.display = 'none';
  document.getElementById('btn-stop').style.display = '';
  progressText.textContent = 'Starting camera...';
  currentCapabilities = {}; currentSettings = {};
  scanner = new Html5Qrcode('reader');
  const config = baseConfig();
  const preferredId = await chooseRearCameraId();
  const startTargets = [];
  if (preferredId) startTargets.push({ deviceId: { exact: preferredId } });
  startTargets.push({ facingMode: { exact: 'environment' } });
  startTargets.push({ facingMode: 'environment' });
  let started = false, lastError = null;
  for (const target of startTargets) {
    try { await scanner.start(target, config, onScanSuccess, () => {}); started = true; break; } catch (err) { lastError = err; }
  }
  if (!started) {
    progressText.textContent = 'Camera error: ' + lastError;
    document.getElementById('btn-start').style.display = '';
    document.getElementById('btn-stop').style.display = 'none';
    scanner = null;
    return;
  }
  await applyBestEffortConstraints();
}
function stopScanner() {
  if (scanner) { scanner.stop().catch(() => {}); scanner = null; }
  document.getElementById('btn-start').style.display = '';
  document.getElementById('btn-stop').style.display = 'none';
  document.getElementById('camera-controls').style.display = 'none';
  currentCapabilities = {}; currentSettings = {}; updateCameraDiag('Camera stopped');
}
function processPhoto(input) {
  if (!input.files || !input.files[0]) return;
  const file = input.files[0];
  stopScanner();
  progressText.textContent = 'Analyzing photo...';
  const tempScanner = new Html5Qrcode('reader');
  tempScanner.scanFileV2(file, false)
    .then(result => {
      const added = addChunkText(result.decodedText, 'photo');
      progressText.textContent = added.status === 'added'
        ? 'QR found in the photo and added to rescue.'
        : added.message;
      if (added.status === 'added') beep();
    })
    .catch(() => { progressText.textContent = 'No QR found in the photo. Try again: closer, steadier, more light.'; })
    .finally(() => { if (typeof tempScanner.clear === 'function') tempScanner.clear().catch(() => {}); });
  input.value = '';
}
document.getElementById('btn-start')?.addEventListener('click', async () => {
  try { await startScanner(); } catch (err) {
    progressText.textContent = 'Camera error: ' + (err && err.message ? err.message : err);
    document.getElementById('btn-start').style.display = '';
    document.getElementById('btn-stop').style.display = 'none';
  }
});
document.getElementById('btn-stop')?.addEventListener('click', stopScanner);
document.getElementById('btn-add-manual')?.addEventListener('click', addManualChunksFromInput);
document.getElementById('btn-clear-collected')?.addEventListener('click', () => resetCollectedChunks());
manualInput?.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
    event.preventDefault();
    addManualChunksFromInput();
  }
});
updateUI();
(function () {
  const toggle = document.getElementById('use_identity');
  const identityPanel = document.getElementById('identity-panel');
  const privatePanel = document.getElementById('private-key-panel');
  function syncIdentity() {
    if (!toggle || !identityPanel) return;
    const usingIdentity = toggle.checked;
    identityPanel.classList.toggle('is-hidden', !usingIdentity);
    if (privatePanel) privatePanel.classList.toggle('is-hidden', usingIdentity);
  }
  if (toggle) { toggle.addEventListener('change', syncIdentity); syncIdentity(); }
  const modal = document.getElementById('credential-modal');
  if (!modal) return;
  const closeTop = document.getElementById('close-credential-modal-top');
  const cancelForm = document.getElementById('cancel-pending-form');
  if (closeTop && cancelForm) closeTop.addEventListener('click', () => cancelForm.submit());
  modal.addEventListener('cancel', (event) => { event.preventDefault(); if (cancelForm) cancelForm.submit(); });
  modal.showModal();
})();
