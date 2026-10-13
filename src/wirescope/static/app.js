(() => {
  'use strict';
  const $ = (selector, parent = document) => parent.querySelector(selector);
  const $$ = (selector, parent = document) => [...parent.querySelectorAll(selector)];
  const state = { token: '', view: 'proxy', running: false, port: 8080, selectedHistory: null, selectedPending: null, pending: [], history: [], repeaterResponse: null, searchTimer: null, lastError: '', siteMap: [], selectedSiteMap: null, findings: [], selectedFinding: null, decoderResult: null, compareResult: null, toolSearchTimer: null, wsConnections: [], wsConnectionOffset: 0, wsConnectionsTotal: 0, wsSelectedConnection: null, wsConnectionDetail: null, wsMessages: [], wsMessageOffset: 0, wsMessagesTotal: 0, wsSelectedMessage: null, wsPayloadDetail: null, wsMessageLimit: 100, wsConnectionLimit: 50, wsConfigLoaded: false, wsConnectionLoaded: false };

  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const bytes = text => new TextEncoder().encode(String(text ?? '')).length;
  const fmtDuration = ms => ms == null ? '—' : `${ms} ms`;
  const fmtStatus = status => status == null ? '—' : String(status);
  const showToast = (message, kind = 'success') => {
    const toast = document.createElement('div');
    toast.className = `toast ${kind}`;
    toast.textContent = message;
    $('#toast-region').append(toast);
    window.setTimeout(() => toast.remove(), 3600);
  };
  const setFooter = text => { $('#footer-status').textContent = text; };

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('X-WireScope-Token', state.token);
    if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    const response = await fetch(path, { ...options, headers, cache: 'no-store' });
    const type = response.headers.get('content-type') || '';
    const payload = type.includes('application/json') ? await response.json() : await response.text();
    if (!response.ok) {
      const detail = payload && typeof payload === 'object' ? payload.detail : null;
      throw new Error(detail || `Request failed (${response.status})`);
    }
    return payload;
  }
  const post = (path, body = {}) => request(path, { method: 'POST', body: JSON.stringify(body) });

  function switchView(name) {
    state.view = name;
    $$('.workspace-view').forEach(view => view.classList.toggle('active', view.id === `view-${name}`));
    $$('.nav-item[data-view]').forEach(button => button.classList.toggle('active', button.dataset.view === name));
    const names = { proxy: 'Proxy', history: 'HTTP History', repeater: 'Repeater', sitemap: 'Site Map', findings: 'Findings', decoder: 'Decoder & Encoder', comparer: 'Comparer', websockets: 'WebSockets', settings: 'Settings & scope' };
    $('#current-crumb').textContent = names[name] || name;
    if (name === 'history') refreshHistory();
    if (name === 'proxy') refreshPending();
    if (name === 'settings') refreshScope();
    if (name === 'repeater') updateRequestSize();
    if (name === 'sitemap') refreshSiteMap();
    if (name === 'findings') refreshFindings();
    if (name === 'comparer') refreshCompareSources();
    if (name === 'websockets') refreshWebSocketConnections();
  }

  function updateProxyStatus(status) {
    state.running = !!status.running;
    if (Number.isInteger(status.port)) state.port = status.port;
    $('#connection-pill').classList.toggle('running', state.running);
    $('#connection-pill').classList.toggle('stopped', !state.running);
    $('#connection-label').textContent = state.running ? `Listening · ${status.port}` : 'Proxy stopped';
    $('#global-proxy-action').textContent = state.running ? 'Stop proxy' : 'Start proxy';
    $('#proxy-main-action').textContent = state.running ? 'Stop listener' : 'Start listener';
    $('#proxy-state-badge').textContent = state.running ? 'LISTENING' : 'OFFLINE';
    $('#proxy-state-badge').className = `state-badge ${state.running ? 'state-on' : 'state-off'}`;
    $('#proxy-description').textContent = state.running ? 'The local listener is ready. Configure a browser or test client to use this proxy.' : 'Start the local listener to capture traffic from a configured browser or test client.';
    $('#proxy-endpoint').textContent = `http://127.0.0.1:${status.port || state.port}`;
    $('#listener-summary').textContent = `127.0.0.1:${status.port || state.port}`;
    $('#intercept-toggle').disabled = !state.running;
    $('#intercept-toggle').checked = !!status.intercept_enabled;
    $('#metric-pending').textContent = String(status.pending_count || 0);
    $('#metric-ca').textContent = status.ca_available ? 'Available' : 'Not created';
    $('#ca-download').disabled = !status.ca_available;
    $('#settings-ca-download').disabled = !status.ca_available;
    $('#ca-path-text').textContent = status.ca_available ? status.ca_path : 'Created after the first proxy start';
    if (document.activeElement !== $('#proxy-port')) $('#proxy-port').value = String(state.port);
    if (status.error && status.error !== state.lastError) showToast(status.error, 'error');
    state.lastError = status.error || '';
  }

  async function refreshStatus(silent = true) {
    try {
      const status = await request('/api/status');
      updateProxyStatus(status);
      if (status.error) setFooter(status.error);
      else setFooter(state.running ? `Proxy listening on 127.0.0.1:${status.port}` : 'Ready');
    } catch (error) {
      if (!silent) showToast(error.message, 'error');
    }
  }

  async function toggleProxy() {
    try {
      if (state.running) {
        await post('/api/proxy/stop');
        showToast('Proxy stopped.');
      } else {
        const result = await post('/api/proxy/start', { port: Number(state.port) || 8080 });
        updateProxyStatus(result);
        showToast(`Proxy listening on 127.0.0.1:${result.port}.`);
      }
      await refreshStatus();
      if (state.view === 'proxy') await refreshPending();
    } catch (error) {
      showToast(error.message, 'error');
      await refreshStatus();
    }
  }

  async function toggleIntercept(enabled) {
    try {
      const result = await post('/api/proxy/intercept', { enabled });
      updateProxyStatus(result);
      showToast(enabled ? 'Request interception enabled.' : 'New requests will pass through automatically. Existing paused requests remain in the queue.');
    } catch (error) {
      $('#intercept-toggle').checked = !enabled;
      showToast(error.message, 'error');
    }
  }

  function toRawRequest(flow) {
    const headers = Array.isArray(flow.request_headers) ? flow.request_headers.map(([k, v]) => `${k}: ${v}`).join('\n') : '';
    const body = flow.request_body_text || '';
    return `${flow.method || 'GET'} ${flow.url || 'http://127.0.0.1/'} HTTP/1.1\n${headers}${headers ? '\n' : ''}\n${body}`;
  }
  function headersText(headers) {
    return Array.isArray(headers) && headers.length ? headers.map(pair => `${pair[0]}: ${pair[1]}`).join('\n') : '(no headers)';
  }
  function requestText(flow) {
    return `${flow.method || 'GET'} ${flow.url || ''} HTTP/1.1\n${headersText(flow.request_headers)}\n\n${flow.request_body_text || ''}${flow.request_truncated ? '\n\n[Request body truncated at 2 MiB]' : ''}`;
  }
  function responseText(flow) {
    const status = flow.status == null ? (flow.error ? `Proxy error: ${flow.error}` : 'No response captured') : `HTTP/1.1 ${flow.status}`;
    return `${status}\n${headersText(flow.response_headers)}\n\n${flow.response_body_text || ''}${flow.response_truncated ? '\n\n[Response body truncated at 2 MiB]' : ''}`;
  }
  function renderPendingRows() {
    const rows = state.pending;
    $('#metric-captured').textContent = String(state.history.length);
    $('#metric-pending').textContent = String(rows.length);
    $('#pending-count-label').textContent = String(rows.length);
    $('#pending-empty').classList.toggle('hidden', rows.length > 0);
    $('#pending-content').classList.toggle('hidden', rows.length === 0);
    if (!rows.length) {
      state.selectedPending = null;
      $('#pending-list-rows').innerHTML = '';
      $('#pending-request-editor').value = '';
      $('#pending-editor-note').textContent = 'No requests waiting.';
      $('#forward-pending').disabled = true;
      $('#drop-pending').disabled = true;
      return;
    }
    if (!rows.some(row => row.id === state.selectedPending)) state.selectedPending = rows[0].id;
    $('#pending-list-rows').innerHTML = rows.map(row => {
      const active = row.id === state.selectedPending;
      const path = (row.url || '').replace(/^https?:\/\/[^/]+/i, '') || '/';
      return `<button class="pending-row ${active ? 'selected' : ''}" data-pending-id="${esc(row.id)}"><span class="pending-first"><span class="method-tag">${esc(row.method)}</span><span class="pending-url">${esc(path)}</span></span><span class="pending-host">${esc(row.host)}</span></button>`;
    }).join('');
    const selected = rows.find(row => row.id === state.selectedPending);
    if (selected) loadPendingDetail(selected.id, true);
  }
  async function loadPendingDetail(id, preserveEditor = true) {
    try {
      const detail = await request(`/api/flows/${encodeURIComponent(id)}`);
      if (state.selectedPending !== id) return;
      if (!preserveEditor || !$('#pending-request-editor').dataset.dirty) {
        $('#pending-request-editor').value = toRawRequest(detail);
        $('#pending-request-editor').dataset.dirty = '';
      }
      $('#pending-editor-note').textContent = `${detail.method} · ${detail.host} · ${detail.request_body_bytes || 0} body bytes`;
      $('#forward-pending').disabled = false;
      $('#drop-pending').disabled = false;
    } catch (error) {
      $('#pending-editor-note').textContent = error.message;
    }
  }
  async function refreshPending() {
    if (state.view !== 'proxy') return;
    try {
      const rows = await request('/api/flows?intercepted=true&limit=100');
      state.pending = rows;
      const all = await request('/api/flows?limit=1000');
      state.history = all;
      renderPendingRows();
    } catch (_) { /* The status poll will surface connection errors when relevant. */ }
  }
  async function forwardSelected() {
    const id = state.selectedPending;
    if (!id) return;
    const raw = $('#pending-request-editor').value;
    if (!raw.trim()) { showToast('Request editor is empty.', 'error'); return; }
    try {
      await post(`/api/flows/${encodeURIComponent(id)}/forward`, { raw_request: raw });
      showToast('Request forwarded.');
      state.pending = state.pending.filter(row => row.id !== id);
      state.selectedPending = null;
      await refreshPending();
    } catch (error) { showToast(error.message, 'error'); }
  }
  async function dropSelected() {
    const id = state.selectedPending;
    if (!id) return;
    try {
      await post(`/api/flows/${encodeURIComponent(id)}/drop`);
      showToast('Request dropped.');
      state.pending = state.pending.filter(row => row.id !== id);
      state.selectedPending = null;
      await refreshPending();
    } catch (error) { showToast(error.message, 'error'); }
  }

  async function refreshHistory() {
    try {
      const search = $('#history-search').value.trim();
      const rows = await request(`/api/flows?limit=1000&search=${encodeURIComponent(search)}`);
      state.history = rows;
      populateCompareSources();
      $('#history-result-count').textContent = `${rows.length} request${rows.length === 1 ? '' : 's'}`;
      $('#metric-captured').textContent = String(rows.length);
      renderHistoryRows();
      if (state.selectedHistory && !rows.some(row => row.id === state.selectedHistory)) {
        state.selectedHistory = null;
        $('#history-detail').classList.add('hidden');
        $('#history-detail-empty').classList.remove('hidden');
      }
    } catch (error) { showToast(error.message, 'error'); }
  }
  function renderHistoryRows() {
    const rows = state.history;
    if (!rows.length) {
      $('#history-rows').innerHTML = '<div class="empty-state compact"><strong>No matching requests</strong><span>Change the filter, or route traffic through the running proxy.</span></div>';
      return;
    }
    $('#history-rows').innerHTML = rows.map(row => {
      const path = (row.url || '').replace(/^https?:\/\/[^/]+/i, '') || '/';
      const bad = row.status != null && row.status >= 400;
      return `<button class="history-row ${row.id === state.selectedHistory ? 'selected' : ''}" data-history-id="${esc(row.id)}"><span class="method-tag">${esc(row.method)}</span><span><span class="history-url">${esc(path)}</span><span class="history-host">${esc(row.host)}</span></span><span class="status-code ${bad ? 'bad' : ''}">${esc(fmtStatus(row.status))}</span><span class="duration-cell">${esc(fmtDuration(row.duration_ms))}</span></button>`;
    }).join('');
  }
  async function openHistoryDetail(id) {
    state.selectedHistory = id;
    renderHistoryRows();
    try {
      const flow = await request(`/api/flows/${encodeURIComponent(id)}`);
      if (state.selectedHistory !== id) return;
      const requestBody = `${flow.method} ${flow.url} HTTP/1.1\n${headersText(flow.request_headers)}\n\n${flow.request_body_text || ''}${flow.request_truncated ? '\n[body truncated]' : ''}`;
      const responseBody = responseText(flow);
      $('#history-detail-empty').classList.add('hidden');
      $('#history-detail').classList.remove('hidden');
      $('#history-detail').innerHTML = `<div class="detail-header"><div class="detail-title-line"><span class="method-tag">${esc(flow.method)}</span><h2>${esc(flow.host)}</h2><span class="status-code ${(flow.status || 0) >= 400 ? 'bad' : ''}">${esc(fmtStatus(flow.status))}</span></div><div class="detail-subtitle">${esc(flow.url)}</div><div class="detail-actions"><button class="button button-primary button-sm" data-action="use-repeater" data-id="${esc(flow.id)}">Send to Repeater ↗</button><button class="button button-secondary button-sm" data-action="copy-raw" data-id="${esc(flow.id)}">Copy request</button></div></div><div class="detail-columns"><div class="detail-column"><div class="detail-column-heading">REQUEST</div><pre class="detail-body">${esc(requestBody)}</pre></div><div class="detail-column"><div class="detail-column-heading">RESPONSE</div><pre class="detail-body ${flow.status == null && !flow.error ? 'empty' : ''}">${esc(responseBody)}</pre></div></div>`;
    } catch (error) { showToast(error.message, 'error'); }
  }

  const wsTime = value => value == null ? '—' : new Date(Number(value) * 1000).toLocaleTimeString();
  const wsBytes = value => `${Number(value || 0).toLocaleString()} B`;
  const wsStatusText = value => ({ open: 'OPEN', closed: 'CLOSED', error: 'ERROR', interrupted: 'INTERRUPTED', rejected: 'REJECTED' })[value] || String(value || 'UNKNOWN').toUpperCase();

  async function refreshWebSocketConnections() {
    const rows = $('#ws-connection-rows');
    if (!rows) return;
    if (!state.wsConnectionLoaded) rows.innerHTML = '<div class="empty-state compact"><strong>Loading WebSocket connections…</strong><span>Reading captured traffic from local SQLite storage.</span></div>';
    try {
      if (!state.wsConfigLoaded) {
        const config = await request('/api/websockets/config');
        $('#ws-size-limit').textContent = `${Math.round(config.max_message_bytes / 1024)} KiB / message`;
        state.wsConfigLoaded = true;
      }
      const query = new URLSearchParams({ search: $('#ws-connection-search').value.trim(), state: $('#ws-connection-state').value, limit: String(state.wsConnectionLimit), offset: String(state.wsConnectionOffset) });
      const result = await request(`/api/websockets/connections?${query}`);
      state.wsConnections = result.connections || [];
      state.wsConnectionsTotal = result.count || 0;
      state.wsConnectionLoaded = true;
      if (state.wsSelectedConnection && !state.wsConnections.some(item => item.id === state.wsSelectedConnection)) {
        state.wsSelectedConnection = null;
        state.wsConnectionDetail = null;
        state.wsSelectedMessage = null;
        state.wsPayloadDetail = null;
        $('#ws-inspector').classList.add('hidden');
        $('#ws-inspector-empty').classList.remove('hidden');
        $('#ws-message-rows').innerHTML = '<div class="empty-state compact"><strong>Select a connection</strong><span>Choose a connection on this page to inspect messages.</span></div>';
      }
      $('#ws-connection-count').textContent = `${state.wsConnectionsTotal} connection${state.wsConnectionsTotal === 1 ? '' : 's'}`;
      $('#ws-connection-page-label').textContent = `Page ${Math.floor(state.wsConnectionOffset / state.wsConnectionLimit) + 1}`;
      $('#ws-connections-prev').disabled = state.wsConnectionOffset <= 0;
      $('#ws-connections-next').disabled = state.wsConnectionOffset + state.wsConnectionLimit >= state.wsConnectionsTotal;
      renderWebSocketConnections();
      updateWebSocketSendAvailability();
      if (!state.wsSelectedConnection && state.wsConnections.length) {
        await selectWebSocketConnection(state.wsConnections[0].id);
      } else if (state.wsSelectedConnection && !state.wsConnectionDetail) {
        await selectWebSocketConnection(state.wsSelectedConnection);
      } else if (state.wsSelectedConnection) {
        await refreshWebSocketMessages(false);
      }
    } catch (error) {
      rows.innerHTML = `<div class="empty-state compact"><strong>Could not load connections</strong><span>${esc(error.message)}</span><button class="button button-secondary button-sm" id="ws-refresh-retry">Retry</button></div>`;
      showToast(error.message, 'error');
    }
  }

  function renderWebSocketConnections() {
    const container = $('#ws-connection-rows');
    if (!state.wsConnections.length) {
      container.innerHTML = '<div class="empty-state compact"><div class="empty-icon">↔</div><strong>No captured WebSocket connections</strong><span>Start the proxy and use a browser or test client through 127.0.0.1:8080. The local lab is documented in README.md.</span></div>';
      return;
    }
    container.innerHTML = state.wsConnections.map(connection => {
      const active = connection.state === 'open';
      return `<button class="ws-connection-row ${connection.id === state.wsSelectedConnection ? 'selected' : ''}" data-ws-connection="${esc(connection.id)}" aria-pressed="${connection.id === state.wsSelectedConnection ? 'true' : 'false'}"><span class="ws-connection-top"><span class="ws-state-dot ${active ? 'active' : ''}"></span><strong>${esc(connection.host || connection.url)}</strong><span class="ws-state-tag ${esc(connection.state)}">${esc(wsStatusText(connection.state))}</span></span><code>${esc(connection.url || '')}</code><span class="ws-connection-meta"><span>${esc(connection.handshake_status ?? '—')}</span><span>${esc(connection.message_count || 0)} messages</span><span>${esc(wsTime(connection.last_seen))}</span></span>${connection.in_scope ? '' : '<span class="ws-scope-warning">OUT OF SCOPE · SEND DISABLED</span>'}</button>`;
    }).join('');
  }

  async function selectWebSocketConnection(id) {
    state.wsSelectedConnection = id;
    state.wsConnectionDetail = null;
    state.wsSelectedMessage = null;
    state.wsPayloadDetail = null;
    state.wsMessageOffset = 0;
    $('#ws-inspector-empty').classList.add('hidden');
    $('#ws-inspector').classList.remove('hidden');
    $('#ws-inspector').innerHTML = '<div class="empty-state compact"><strong>Loading connection details…</strong></div>';
    $('#ws-message-rows').innerHTML = '<div class="empty-state compact"><strong>Loading messages…</strong></div>';
    renderWebSocketConnections();
    try {
      const detail = await request(`/api/websockets/connections/${encodeURIComponent(id)}`);
      if (state.wsSelectedConnection !== id) return;
      state.wsConnectionDetail = detail;
      renderWebSocketInspector();
      updateWebSocketSendAvailability();
      await refreshWebSocketMessages(true);
    } catch (error) {
      $('#ws-inspector').innerHTML = `<div class="empty-state compact"><strong>Could not load connection</strong><span>${esc(error.message)}</span></div>`;
      showToast(error.message, 'error');
    }
  }

  function renderWebSocketInspector() {
    const c = state.wsConnectionDetail;
    if (!c) return;
    const reqHeaders = (c.request_headers || []).map(([k, v]) => `${k}: ${v}`).join('\n') || '(no captured request headers)';
    const resHeaders = (c.response_headers || []).map(([k, v]) => `${k}: ${v}`).join('\n') || '(no captured response headers)';
    const terminal = c.close_code != null ? `Close code ${c.close_code}${c.close_reason ? ` · ${c.close_reason}` : ''}` : (c.error || (c.state === 'open' ? 'Connection is open' : 'No close code observed'));
    $('#ws-inspector').innerHTML = `<div class="ws-inspector-content"><div class="ws-inspector-heading"><div><span class="eyebrow">SELECTED CONNECTION</span><h2>${esc(c.host || 'WebSocket')}</h2></div><span class="ws-state-tag ${esc(c.state)}">${esc(wsStatusText(c.state))}</span></div><code class="ws-full-url">${esc(c.url)}</code><div class="endpoint-stats"><span class="endpoint-chip">Handshake ${esc(c.handshake_status ?? 'unknown')}</span><span class="endpoint-chip">${esc(c.scheme)}</span><span class="endpoint-chip">${esc(c.remote_ip || 'Peer IP unavailable')}</span><span class="endpoint-chip">${esc(c.message_count || 0)} captured</span></div><p class="ws-terminal-note">${esc(terminal)}</p><div class="ws-inspector-section"><h3>Handshake request headers</h3><pre class="ws-header-view">${esc(reqHeaders)}</pre></div><div class="ws-inspector-section"><h3>Handshake response headers</h3><pre class="ws-header-view">${esc(resHeaders)}</pre></div><div class="ws-inspector-section"><div class="ws-inspector-section-title"><h3>Selected message payload</h3><select id="ws-payload-format" class="filter-select" aria-label="Payload display format"><option value="auto">Auto</option><option value="text">Text</option><option value="hex">Hex</option><option value="base64">Base64</option></select></div><p id="ws-payload-meta" class="muted-note">Select a message to inspect its exact stored bytes.</p><pre id="ws-message-payload" class="ws-payload-view">No message selected.</pre></div><div class="ws-inspector-section"><div class="ws-inspector-section-title"><h3>Send a message</h3><span class="subtle">Manual · user initiated</span></div><label class="editor-label" for="ws-send-format">Payload format<select id="ws-send-format" class="filter-select"><option value="text">Text (UTF-8)</option><option value="binary">Binary (Base64 input)</option></select></label><textarea id="ws-send-editor" class="code-editor ws-send-editor" spellcheck="false" aria-label="WebSocket message to send" placeholder="Enter a message. Binary mode expects Base64…"></textarea><div class="ws-send-actions"><button id="ws-send-button" class="button button-primary button-sm" disabled>Send to server</button><span id="ws-send-status" class="muted-note" role="status">Select an open, in-scope connection.</span></div><p class="muted-note">WireScope sends only through this established connection. It never opens a new WebSocket from this editor.</p></div>${c.flow_id ? `<button class="button button-secondary button-sm" data-action="inspect-capture" data-id="${esc(c.flow_id)}">Open handshake in HTTP History</button>` : ''}</div>`;
    renderWebSocketPayload();
  }

  async function refreshWebSocketMessages(reset = false) {
    const id = state.wsSelectedConnection;
    if (!id) return;
    if (reset) state.wsMessageOffset = 0;
    const query = new URLSearchParams({ search: $('#ws-message-search').value.trim(), direction: $('#ws-message-direction').value, opcode: $('#ws-message-opcode').value, limit: String(state.wsMessageLimit), offset: String(state.wsMessageOffset) });
    try {
      const result = await request(`/api/websockets/connections/${encodeURIComponent(id)}/messages?${query}`);
      if (state.wsSelectedConnection !== id) return;
      state.wsMessages = result.messages || [];
      state.wsMessagesTotal = result.count || 0;
      $('#ws-message-count').textContent = `${state.wsMessagesTotal} message${state.wsMessagesTotal === 1 ? '' : 's'}`;
      $('#ws-message-subtitle').textContent = `${state.wsConnectionDetail?.host || 'Connection'} · ${wsStatusText(state.wsConnectionDetail?.state)}`;
      $('#ws-messages-prev').disabled = state.wsMessageOffset <= 0;
      $('#ws-messages-next').disabled = state.wsMessageOffset + state.wsMessageLimit >= state.wsMessagesTotal;
      renderWebSocketMessages();
      if (state.wsSelectedMessage && !state.wsMessages.some(item => Number(item.id) === Number(state.wsSelectedMessage))) {
        // Keep the payload inspector intact across background refreshes; only clear if filters exclude it.
      }
    } catch (error) {
      $('#ws-message-rows').innerHTML = `<div class="empty-state compact"><strong>Could not load messages</strong><span>${esc(error.message)}</span></div>`;
      showToast(error.message, 'error');
    }
  }

  function renderWebSocketMessages() {
    const container = $('#ws-message-rows');
    if (!state.wsMessages.length) {
      container.innerHTML = '<div class="empty-state compact"><strong>No matching messages</strong><span>Change the filters or wait for traffic to pass through the selected connection.</span></div>';
      return;
    }
    container.innerHTML = state.wsMessages.map(message => {
      const type = Number(message.opcode) === 1 ? 'TEXT' : 'BINARY';
      const arrow = message.direction === 'client_to_server' ? '↑' : '↓';
      return `<button class="ws-message-row ${Number(message.id) === Number(state.wsSelectedMessage) ? 'selected' : ''}" data-ws-message="${esc(message.id)}" aria-pressed="${Number(message.id) === Number(state.wsSelectedMessage) ? 'true' : 'false'}"><span class="ws-message-leading ${message.direction === 'client_to_server' ? 'outgoing' : 'incoming'}">${arrow}</span><span class="ws-message-main"><span><strong>${esc(type)}</strong>${message.source === 'user' ? '<em class="ws-user-tag">USER SENT</em>' : '<em class="ws-captured-tag">CAPTURED</em>'}</span><small>${esc(wsTime(message.timestamp))} · ${esc(message.direction === 'client_to_server' ? 'Client → server' : 'Server → client')}</small><small>${esc(message.payload_size)} bytes${message.truncated ? ' · STORED PREFIX ONLY' : ''}</small></span></button>`;
    }).join('');
  }

  async function openWebSocketMessage(id) {
    const connectionId = state.wsSelectedConnection;
    if (!connectionId) return;
    state.wsSelectedMessage = Number(id);
    renderWebSocketMessages();
    try {
      const detail = await request(`/api/websockets/connections/${encodeURIComponent(connectionId)}/messages/${encodeURIComponent(id)}`);
      if (state.wsSelectedConnection !== connectionId || Number(state.wsSelectedMessage) !== Number(id)) return;
      state.wsPayloadDetail = detail;
      renderWebSocketPayload();
    } catch (error) { showToast(error.message, 'error'); }
  }

  function renderWebSocketPayload() {
    const message = state.wsPayloadDetail;
    const view = $('#ws-message-payload');
    if (!view) return;
    if (!message) {
      view.textContent = 'No message selected.';
      if ($('#ws-payload-meta')) $('#ws-payload-meta').textContent = 'Select a message to inspect its exact stored bytes.';
      return;
    }
    const format = $('#ws-payload-format')?.value || 'auto';
    let value;
    if (format === 'text') value = message.payload_text == null ? '[Not valid UTF-8 text; binary bytes preserved below.]' : message.payload_text;
    else if (format === 'hex') value = message.payload_hex || '';
    else if (format === 'base64') value = message.payload_base64 || '';
    else value = Number(message.opcode) === 1 && message.payload_text != null ? message.payload_text : (message.payload_hex || '');
    view.textContent = value;
    const source = message.source === 'user' ? 'Manually sent by user' : 'Captured from traffic';
    $('#ws-payload-meta').textContent = `${source} · ${Number(message.opcode) === 1 ? 'Text opcode 1' : 'Binary opcode 2'} · ${message.payload_size} original bytes · ${message.stored_bytes ?? Math.floor((message.payload_base64 || '').length * 3 / 4)} stored bytes${message.truncated ? ' · TRUNCATED PREFIX' : ''}${message.text_decode_error ? ' · Invalid UTF-8' : ''}`;
  }

  function updateWebSocketSendAvailability() {
    const button = $('#ws-send-button');
    if (!button) return;
    const row = state.wsConnections.find(item => item.id === state.wsSelectedConnection);
    const detail = state.wsConnectionDetail;
    const canSend = !!state.running && !!row && row.state === 'open' && row.in_scope === true && !!detail && detail.state === 'open' && detail.in_scope === true;
    button.disabled = !canSend;
    const note = $('#ws-send-status');
    if (note) note.textContent = !detail ? 'Select a connection.' : !state.running ? 'Start the proxy to enable sending.' : !detail.in_scope ? 'Target is out of scope; sending is blocked.' : detail.state !== 'open' ? `Connection is ${detail.state}; sending is blocked.` : canSend ? 'Ready · sends only through this live connection.' : 'Waiting for live connection state.';
  }

  async function sendWebSocketMessage() {
    const button = $('#ws-send-button');
    if (!state.wsSelectedConnection || button.disabled) return;
    const format = $('#ws-send-format').value;
    button.disabled = true;
    button.textContent = 'Sending…';
    $('#ws-send-status').textContent = 'Sending the manually initiated message…';
    try {
      const result = await post(`/api/websockets/connections/${encodeURIComponent(state.wsSelectedConnection)}/send`, { payload: $('#ws-send-editor').value, binary: format === 'binary' });
      $('#ws-send-status').textContent = `Sent ${result.payload_bytes} bytes · recorded as USER SENT.`;
      showToast('WebSocket message sent.');
      await refreshWebSocketConnections();
      await refreshWebSocketMessages(false);
    } catch (error) {
      $('#ws-send-status').textContent = error.message;
      showToast(error.message, 'error');
    } finally {
      button.textContent = 'Send to server';
      updateWebSocketSendAvailability();
    }
  }

  async function sendRepeater() {
    const button = $('#repeater-send');
    button.disabled = true;
    button.textContent = 'Sending…';
    $('#repeater-response-meta').textContent = 'Request in progress';
    $('#repeater-response').textContent = 'Waiting for the target response…';
    try {
      const result = await post('/api/repeater/send', { raw_request: $('#repeater-request').value, timeout: Number($('#repeater-timeout').value) || 10 });
      state.repeaterResponse = result;
      const headers = result.headers.map(([key, value]) => `${key}: ${value}`).join('\n');
      $('#repeater-response').textContent = `HTTP/1.1 ${result.status} ${result.reason}\n${headers}\n\n${result.body}${result.truncated ? '\n\n[Response truncated at 2 MiB]' : ''}`;
      $('#repeater-response-meta').textContent = `${result.status} · ${result.duration_ms} ms · ${result.body_bytes} bytes${result.truncated ? ' · truncated' : ''}`;
      $('#copy-response').disabled = false;
      showToast(`Response received: ${result.status}.`);
      setFooter(`Repeater response ${result.status}`);
    } catch (error) {
      $('#repeater-response').textContent = `Request failed\n\n${error.message}`;
      $('#repeater-response-meta').textContent = 'Request failed';
      $('#copy-response').disabled = true;
      showToast(error.message, 'error');
    } finally {
      button.disabled = false;
      button.innerHTML = 'Send request <span class="send-arrow">↗</span>';
      updateRequestSize();
    }
  }
  function updateRequestSize() { $('#repeater-request-size').textContent = `${bytes($('#repeater-request').value).toLocaleString()} bytes`; }
  async function useInRepeater(id) {
    try {
      const flow = await request(`/api/flows/${encodeURIComponent(id)}`);
      $('#repeater-request').value = `${flow.method} ${flow.url} HTTP/1.1\n${headersText(flow.request_headers)}\n\n${flow.request_body_text || ''}`;
      updateRequestSize();
      switchView('repeater');
      showToast('Request loaded into Repeater.');
    } catch (error) { showToast(error.message, 'error'); }
  }
  async function copyHistoryRequest(id) {
    try {
      const flow = await request(`/api/flows/${encodeURIComponent(id)}`);
      const text = `${flow.method} ${flow.url} HTTP/1.1\n${headersText(flow.request_headers)}\n\n${flow.request_body_text || ''}`;
      await copyText(text);
      showToast('Request copied.');
    } catch (error) { showToast(error.message, 'error'); }
  }
  async function copyText(value) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(value);
    const textarea = document.createElement('textarea'); textarea.value = value; textarea.style.position = 'fixed'; textarea.style.opacity = '0'; document.body.append(textarea); textarea.select();
    const ok = document.execCommand('copy'); textarea.remove(); if (!ok) throw new Error('Clipboard access unavailable');
  }

  async function downloadCA() {
    try {
      const response = await fetch('/api/ca', { headers: { 'X-WireScope-Token': state.token }, cache: 'no-store' });
      if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.detail || 'CA certificate not available'); }
      const objectUrl = URL.createObjectURL(await response.blob());
      const link = document.createElement('a'); link.href = objectUrl; link.download = 'wirescope-ca-cert.pem'; document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(objectUrl);
      showToast('CA certificate exported. Install it manually only in a dedicated test browser/profile.');
    } catch (error) { showToast(error.message, 'error'); }
  }

  async function refreshScope() {
    try {
      const data = await request('/api/scope');
      const rules = data.rules || [];
      $('#scope-rules').innerHTML = rules.length ? rules.map(rule => `<div class="scope-rule"><span class="scope-mode ${esc(rule.mode)}">${rule.mode === 'include' ? 'INCLUDE' : 'EXCLUDE'}</span><code title="${esc(rule.pattern)}">${esc(rule.pattern)}</code><button class="delete-rule" data-delete-rule="${esc(rule.id)}" aria-label="Delete ${esc(rule.pattern)}" title="Delete rule">×</button></div>`).join('') : '<div class="muted-note">No custom rules. Loopback is in scope by default unless explicitly excluded.</div>';
    } catch (error) { showToast(error.message, 'error'); }
  }
  async function addScope(event) {
    event.preventDefault();
    const pattern = $('#scope-pattern').value.trim(); const mode = $('#scope-mode').value;
    try { await post('/api/scope', { pattern, mode }); $('#scope-pattern').value = ''; await refreshScope(); showToast(`${mode === 'include' ? 'Included' : 'Excluded'} ${pattern}.`); }
    catch (error) { showToast(error.message, 'error'); }
  }
  async function deleteScope(id) {
    try { await request(`/api/scope/${encodeURIComponent(id)}`, { method: 'DELETE' }); await refreshScope(); showToast('Scope rule removed.'); }
    catch (error) { showToast(error.message, 'error'); }
  }

  function queryString(values) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(values)) if (value !== '' && value != null) params.set(key, value);
    return params.toString();
  }

  async function refreshSiteMap() {
    if (state.view !== 'sitemap') return;
    const holder = $('#sitemap-rows');
    holder.innerHTML = '<div class="empty-state compact"><strong>Loading endpoints…</strong><span>Reading persisted traffic from SQLite.</span></div>';
    try {
      const query = queryString({
        search: $('#sitemap-search').value.trim(), host: $('#sitemap-host').value.trim(),
        method: $('#sitemap-method').value, content_type: $('#sitemap-type').value,
        status: $('#sitemap-status').value, scope: $('#sitemap-scope').value, limit: '2000'
      });
      const data = await request(`/api/sitemap?${query}`);
      state.siteMap = data.entries || [];
      renderSiteMapRows();
    } catch (error) {
      holder.innerHTML = `<div class="empty-state compact"><strong>Could not load Site Map</strong><span>${esc(error.message)}</span></div>`;
    }
  }

  function renderSiteMapRows() {
    const holder = $('#sitemap-rows');
    if (!state.siteMap.length) {
      holder.innerHTML = '<div class="empty-state compact"><strong>No observed endpoints match</strong><span>Route traffic through the local proxy, or loosen the filters. WireScope does not crawl targets.</span></div>';
      return;
    }

    // Build a host → path-segment tree strictly from observed endpoint records.
    const hosts = new Map();
    for (const entry of state.siteMap) {
      if (!hosts.has(entry.host)) hosts.set(entry.host, { segment: '', entries: [], children: new Map() });
      let node = hosts.get(entry.host);
      const segments = String(entry.path || '/').split('/').filter(Boolean);
      if (!segments.length) { node.entries.push(entry); continue; }
      for (const segment of segments) {
        if (!node.children.has(segment)) node.children.set(segment, { segment, entries: [], children: new Map() });
        node = node.children.get(segment);
      }
      node.entries.push(entry);
    }

    const countNode = node => node.entries.length + [...node.children.values()].reduce((sum, child) => sum + countNode(child), 0);
    const renderEntry = entry => {
      const active = entry.id === state.selectedSiteMap;
      const status = entry.statuses.length ? entry.statuses.join(', ') : '—';
      const type = entry.content_types.join(', ') || 'unknown type';
      return `<button class="sitemap-row ${active ? 'selected' : ''}" data-sitemap-id="${esc(entry.id)}" aria-pressed="${active}"><span class="sitemap-endpoint"><strong><span class="method-tag">${esc(entry.method)}</span> ${esc(entry.path)}</strong><small>${esc(type)} · ${esc(entry.query_parameters.length)} parameter name(s)</small></span><span class="sitemap-entry-meta"><span class="status-code">${esc(status)}</span><span class="sitemap-request-count">${esc(entry.request_count)} req</span><span class="scope-state ${entry.in_scope ? '' : 'out'}">${entry.in_scope ? 'In scope' : 'Out of scope'}</span></span></button>`;
    };
    const renderNode = node => {
      const entries = node.entries.map(renderEntry).join('');
      const children = [...node.children.values()].sort((a, b) => a.segment.localeCompare(b.segment)).map(child => renderNode(child)).join('');
      if (!node.segment) return entries + children;
      const count = countNode(node);
      return `<details class="sitemap-path-group" open><summary><span class="sitemap-tree-chevron" aria-hidden="true">⌄</span><code>${esc(node.segment)}</code><small>${count} endpoint${count === 1 ? '' : 's'}</small></summary><div class="sitemap-tree-children">${entries}${children}</div></details>`;
    };

    holder.innerHTML = [...hosts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([host, root]) => {
      const count = countNode(root);
      return `<details class="sitemap-host-group" open><summary><span class="sitemap-tree-chevron sitemap-host-glyph" aria-hidden="true">⌄</span><strong>${esc(host)}</strong><small>${count} endpoint${count === 1 ? '' : 's'}</small></summary><div class="sitemap-host-children">${renderNode(root)}</div></details>`;
    }).join('');
  }

  async function openSiteMapEntry(id) {
    const entry = state.siteMap.find(item => item.id === id);
    if (!entry) return;
    state.selectedSiteMap = id;
    renderSiteMapRows();
    $('#sitemap-detail-empty').classList.add('hidden');
    $('#sitemap-detail').classList.remove('hidden');
    $('#sitemap-detail').innerHTML = '<div class="empty-state compact"><strong>Loading endpoint history…</strong></div>';
    try {
      const query = queryString({ origin: entry.origin, path: entry.path, method: entry.method, limit: '20' });
      const data = await request(`/api/sitemap/endpoint?${query}`);
      if (state.selectedSiteMap !== id) return;
      const statuses = entry.statuses.length ? entry.statuses.join(', ') : 'No response status recorded';
      const params = entry.query_parameters.length ? entry.query_parameters.map(p => `<span class="endpoint-chip">${esc(p)}</span>`).join('') : '<span class="muted-note">No query parameters observed.</span>';
      const captures = (data.flows || []).map(flow => `<div class="related-capture"><span><strong><span class="method-tag">${esc(flow.method)}</span> ${esc(flow.status ?? 'No response')}</strong><small>${esc(new Date(flow.started_at * 1000).toLocaleString())} · ${esc(flow.url)}</small></span><button class="button button-secondary button-sm" data-action="inspect-capture" data-id="${esc(flow.id)}">Inspect</button></div>`).join('');
      $('#sitemap-detail').innerHTML = `<div class="endpoint-heading"><h2>${esc(entry.method)} ${esc(entry.path)}</h2><p>${esc(entry.origin)} · ${entry.in_scope ? '<span class="scope-state">In scope</span>' : '<span class="scope-state out">Out of scope</span>'}</p></div><div class="endpoint-stats"><span class="endpoint-chip">${esc(entry.request_count)} captured request(s)</span><span class="endpoint-chip">Status: ${esc(statuses)}</span><span class="endpoint-chip">Content type: ${esc(entry.content_types.join(', ') || 'unknown')}</span></div><div class="finding-detail-section"><h3>Query parameter names</h3><div class="parameter-list">${params}</div></div><div class="finding-detail-section"><h3>Associated captures (${data.count})</h3>${captures || '<p>No matching capture remains in HTTP history.</p>'}</div>`;
    } catch (error) {
      $('#sitemap-detail').innerHTML = `<div class="empty-state compact"><strong>Could not load endpoint captures</strong><span>${esc(error.message)}</span></div>`;
    }
  }

  async function refreshFindings() {
    if (state.view !== 'findings') return;
    const holder = $('#findings-rows');
    holder.innerHTML = '<div class="empty-state compact"><strong>Loading findings…</strong></div>';
    try {
      const query = queryString({ search: $('#findings-search').value.trim(), severity: $('#findings-severity').value, status: $('#findings-status').value, limit: '1000' });
      const data = await request(`/api/findings?${query}`);
      state.findings = data.findings || [];
      $('#findings-count').textContent = `${data.count} finding${data.count === 1 ? '' : 's'}`;
      renderFindings();
    } catch (error) {
      holder.innerHTML = `<div class="empty-state compact"><strong>Could not load findings</strong><span>${esc(error.message)}</span></div>`;
    }
  }

  function renderFindings() {
    const holder = $('#findings-rows');
    if (!state.findings.length) {
      holder.innerHTML = '<div class="empty-state compact"><strong>No findings match</strong><span>Captured responses are analyzed after the proxy receives them. Use “Analyze saved history” to analyze older captures.</span></div>';
      if (state.selectedFinding) { state.selectedFinding = null; $('#finding-detail').classList.add('hidden'); $('#finding-detail-empty').classList.remove('hidden'); }
      return;
    }
    holder.innerHTML = state.findings.map(f => `<button class="finding-row ${f.id === state.selectedFinding ? 'selected' : ''}" data-finding-id="${esc(f.id)}" aria-pressed="${f.id === state.selectedFinding}"><span class="finding-row-top"><span class="severity-tag ${esc(f.severity)}">${esc(f.severity)}</span><span class="finding-status">${esc(f.status.replace('_', ' '))}</span><span class="confidence-tag">${esc(f.confidence)} confidence</span></span><strong>${esc(f.title)}</strong><small>${esc(f.url)}</small></button>`).join('');
  }

  async function openFinding(id) {
    state.selectedFinding = id;
    renderFindings();
    try {
      const f = await request(`/api/findings/${encodeURIComponent(id)}`);
      if (state.selectedFinding !== id) return;
      $('#finding-detail-empty').classList.add('hidden');
      $('#finding-detail').classList.remove('hidden');
      const options = [['open','Open'],['false_positive','False positive'],['resolved','Resolved']].map(([value,label]) => `<option value="${value}" ${f.status === value ? 'selected' : ''}>${label}</option>`).join('');
      $('#finding-detail').innerHTML = `<div class="finding-detail-heading"><div class="finding-row-top"><span class="severity-tag ${esc(f.severity)}">${esc(f.severity)}</span><span class="confidence-tag">${esc(f.confidence)} confidence</span><span class="finding-status">${esc(f.status.replace('_',' '))}</span></div><h2>${esc(f.title)}</h2><p>${esc(f.url)}</p><p>Rule: <code>${esc(f.rule_id)}</code></p></div><div class="finding-controls"><label class="control-label" for="finding-status-select">Review status<select id="finding-status-select" class="filter-select">${options}</select></label><button class="button button-secondary button-sm" id="finding-status-save" data-finding-status-id="${esc(f.id)}">Save status</button><button class="button button-primary button-sm" data-action="finding-history" data-id="${esc(f.flow_id)}">Open captured traffic</button></div><div class="finding-detail-section"><h3>Evidence</h3><pre class="finding-evidence">${esc(f.evidence)}</pre></div><div class="finding-detail-section"><h3>Why this may matter</h3><p>${esc(f.explanation)}</p></div><div class="finding-detail-section"><h3>Recommended remediation</h3><p>${esc(f.remediation)}</p></div><div class="finding-detail-section"><h3>Provenance</h3><p>Source flow <code>${esc(f.flow_id)}</code>. This passive rule did not send any additional request. Review the original capture and application context before treating this as a confirmed vulnerability.</p></div>`;
    } catch (error) { showToast(error.message, 'error'); }
  }

  async function saveFindingStatus(id) {
    try {
      const status = $('#finding-status-select').value;
      await post(`/api/findings/${encodeURIComponent(id)}/status`, { status });
      showToast(`Finding marked ${status.replace('_', ' ')}.`);
      await refreshFindings();
      await openFinding(id);
    } catch (error) { showToast(error.message, 'error'); }
  }

  async function reanalyzeSavedHistory() {
    const button = $('#findings-reanalyze');
    button.disabled = true; button.textContent = 'Queueing…';
    try {
      const result = await request('/api/findings/reanalyze?limit=1000', { method: 'POST' });
      showToast(`Queued passive analysis for ${result.queued} saved response(s). No new requests will be sent.`);
      window.setTimeout(() => refreshFindings(), 1000);
      window.setTimeout(() => refreshFindings(), 2500);
    } catch (error) { showToast(error.message, 'error'); }
    finally { button.disabled = false; button.textContent = 'Analyze saved history'; }
  }

  function decoderMessage(message, kind = '') {
    const node = $('#decoder-message'); node.textContent = message; node.className = `tool-message ${kind}`.trim();
  }
  function updateDecoderCounts() {
    $('#decoder-input-meta').textContent = `${bytes($('#decoder-input').value).toLocaleString()} bytes`;
    $('#decoder-output-meta').textContent = $('#decoder-output').value ? `${bytes($('#decoder-output').value).toLocaleString()} bytes displayed` : 'No output yet';
  }
  async function runTransform() {
    const button = $('#decoder-transform'); button.disabled = true; button.textContent = 'Transforming…';
    decoderMessage('Transforming locally…');
    try {
      const result = await post('/api/tools/transform', { operation: $('#decoder-operation').value, value: $('#decoder-input').value });
      state.decoderResult = result;
      if (result.binary) {
        $('#decoder-output').value = `Binary output (${result.bytes} bytes)\nHEX:\n${result.hex}\n\nBASE64:\n${result.base64}`;
        decoderMessage(result.warning || 'Binary data detected; exact bytes are represented as hex and Base64.', 'error');
      } else {
        $('#decoder-output').value = result.output;
        decoderMessage(`Completed · ${result.bytes} output bytes · UTF-8 text preserved.`, 'success');
      }
      $('#decoder-swap').disabled = !!result.binary;
      updateDecoderCounts();
    } catch (error) {
      state.decoderResult = null; $('#decoder-output').value = ''; $('#decoder-swap').disabled = false;
      decoderMessage(error.message, 'error'); updateDecoderCounts();
    } finally { button.disabled = false; button.textContent = 'Transform'; }
  }
  function swapDecoder() {
    if (state.decoderResult?.binary) { decoderMessage('Cannot swap binary output as text; use the explicit hex or Base64 representation.', 'error'); return; }
    const input = $('#decoder-input'), output = $('#decoder-output');
    const oldInput = input.value; input.value = output.value; output.value = oldInput;
    const inverse = { url_encode: 'url_decode', url_decode: 'url_encode', base64_encode: 'base64_decode', base64_decode: 'base64_encode', hex_encode: 'hex_decode', hex_decode: 'hex_encode', html_encode: 'html_decode', html_decode: 'html_encode' };
    const mode = $('#decoder-operation'); if (inverse[mode.value]) mode.value = inverse[mode.value];
    state.decoderResult = null; updateDecoderCounts(); decoderMessage('Input and output swapped. Choose Transform to run the selected operation.', '');
  }
  function clearDecoder() {
    $('#decoder-input').value = ''; $('#decoder-output').value = ''; state.decoderResult = null;
    $('#decoder-swap').disabled = false; updateDecoderCounts(); decoderMessage('Cleared. UTF-8 text input · maximum 2 MiB.');
  }

  function populateCompareSources() {
    for (const side of ['left', 'right']) {
      const select = $(`#compare-${side}-flow`);
      if (!select) continue;
      const previous = select.value;
      const options = state.history.map(flow => {
        const label = `${flow.method} · ${flow.status ?? 'pending'} · ${(flow.url || '').slice(0, 110)}`;
        return `<option value="${esc(flow.id)}">${esc(label)}</option>`;
      }).join('');
      select.innerHTML = `<option value="">Choose captured request…</option>${options}`;
      if ([...select.options].some(option => option.value === previous)) select.value = previous;
    }
  }

  async function refreshCompareSources() {
    // Refresh from persisted history on entry; traffic may have arrived while another workspace was open.
    try {
      const rows = await request('/api/flows?limit=1000');
      state.history = rows;
      populateCompareSources();
    } catch (error) {
      populateCompareSources();
      showToast(`Could not refresh captured comparison sources: ${error.message}`, 'error');
    }
  }

  async function loadCompareSource(side) {
    const id = $(`#compare-${side}-flow`).value;
    if (!id) { showToast('Select a captured HTTP message first.', 'error'); return; }
    try {
      const flow = await request(`/api/flows/${encodeURIComponent(id)}`);
      const kind = $(`#compare-${side}-kind`).value;
      $(`#compare-${side}`).value = kind === 'response' ? responseText(flow) : requestText(flow);
      showToast(`${side === 'left' ? 'Left' : 'Right'} input loaded from HTTP History.`);
    } catch (error) { showToast(error.message, 'error'); }
  }
  async function runCompare() {
    const button = $('#compare-run'); button.disabled = true; button.textContent = 'Comparing…';
    $('#compare-summary').textContent = 'Computing line differences locally…';
    try {
      const result = await post('/api/tools/compare', { left: $('#compare-left').value, right: $('#compare-right').value, mode: $('#compare-mode').value });
      state.compareResult = result;
      $('#compare-summary').textContent = result.identical ? 'Inputs are identical.' : `${result.added} added · ${result.removed} removed · ${result.modified} modified`;
      $('#compare-copy-diff').disabled = false;
      if (result.identical) {
        $('#compare-result').innerHTML = '<div class="empty-state compact"><strong>Inputs are identical</strong><span>No line differences were found in the selected comparison mode.</span></div>';
        return;
      }
      // Diff computation is off the UI thread; also cap DOM work for very large captures.
      // The copy action retains the full server-produced unified diff even when this view is clipped.
      const displayLimit = 3000;
      const visibleRows = result.rows.slice(0, displayLimit);
      const lines = visibleRows.map(row => {
        const className = row.type === 'context' ? 'context' : row.type;
        const leftNum = row.left_line == null ? '' : row.left_line;
        const rightNum = row.right_line == null ? '' : row.right_line;
        const leftText = row.type === 'added' ? '' : row.left;
        const rightText = row.type === 'removed' ? '' : row.right;
        return `<div class="diff-line ${className}"><span class="diff-line-number">${esc(leftNum)}</span>${esc(leftText)}</div><div class="diff-line right ${className}"><span class="diff-line-number">${esc(rightNum)}</span>${esc(rightText)}</div>`;
      }).join('');
      const clippingNote = result.rows.length > displayLimit ? `<div class="diff-truncation-note">Showing the first ${displayLimit.toLocaleString()} diff rows of ${result.rows.length.toLocaleString()}. Copy unified diff for the complete comparison.</div>` : '';
      $('#compare-result').innerHTML = `${clippingNote}<div class="diff-header">LEFT INPUT</div><div class="diff-header">RIGHT INPUT</div><div class="diff-grid">${lines}</div>`;
    } catch (error) {
      $('#compare-summary').textContent = error.message;
      $('#compare-result').innerHTML = `<div class="empty-state compact"><strong>Comparison failed</strong><span>${esc(error.message)}</span></div>`;
      $('#compare-copy-diff').disabled = true;
    } finally { button.disabled = false; button.textContent = 'Compare'; }
  }

  function invalidateCompareResult() {
    state.compareResult = null;
    $('#compare-copy-diff').disabled = true;
    $('#compare-summary').textContent = 'Inputs changed. Run Compare to refresh differences.';
  }

  async function goToHistory(id) {
    switchView('history');
    $('#history-search').value = '';
    await refreshHistory();
    await openHistoryDetail(id);
  }

  document.addEventListener('click', async event => {
    const nav = event.target.closest('[data-view]');
    if (nav) { switchView(nav.dataset.view); return; }
    if (event.target.closest('#global-proxy-action') || event.target.closest('#proxy-main-action')) { await toggleProxy(); return; }
    if (event.target.closest('#copy-endpoint')) { try { await copyText($('#proxy-endpoint').textContent); showToast('Proxy address copied.'); } catch (e) { showToast(e.message, 'error'); } return; }
    if (event.target.closest('#ca-download') || event.target.closest('#settings-ca-download')) { await downloadCA(); return; }
    if (event.target.closest('#forward-pending')) { await forwardSelected(); return; }
    if (event.target.closest('#drop-pending')) { await dropSelected(); return; }
    if (event.target.closest('#history-refresh')) { await refreshHistory(); return; }
    if (event.target.closest('#sitemap-refresh')) { await refreshSiteMap(); return; }
    if (event.target.closest('#findings-refresh')) { await refreshFindings(); return; }
    if (event.target.closest('#findings-reanalyze')) { await reanalyzeSavedHistory(); return; }
    if (event.target.closest('#decoder-transform')) { await runTransform(); return; }
    if (event.target.closest('#decoder-swap')) { swapDecoder(); return; }
    if (event.target.closest('#decoder-clear')) { clearDecoder(); return; }
    if (event.target.closest('#decoder-copy')) { try { await copyText($('#decoder-output').value); showToast('Output copied.'); } catch (e) { showToast(e.message, 'error'); } return; }
    if (event.target.closest('#compare-run')) { await runCompare(); return; }
    if (event.target.closest('#compare-left-load')) { await loadCompareSource('left'); return; }
    if (event.target.closest('#compare-right-load')) { await loadCompareSource('right'); return; }
    if (event.target.closest('#compare-copy-diff')) { try { await copyText(state.compareResult?.unified_diff || ''); showToast('Unified diff copied.'); } catch (e) { showToast(e.message, 'error'); } return; }
    if (event.target.closest('#ws-refresh') || event.target.closest('#ws-refresh-retry')) { await refreshWebSocketConnections(); return; }
    if (event.target.closest('#ws-connections-prev')) { state.wsConnectionOffset = Math.max(0, state.wsConnectionOffset - state.wsConnectionLimit); await refreshWebSocketConnections(); return; }
    if (event.target.closest('#ws-connections-next')) { state.wsConnectionOffset += state.wsConnectionLimit; await refreshWebSocketConnections(); return; }
    if (event.target.closest('#ws-messages-prev')) { state.wsMessageOffset = Math.max(0, state.wsMessageOffset - state.wsMessageLimit); await refreshWebSocketMessages(); return; }
    if (event.target.closest('#ws-messages-next')) { state.wsMessageOffset += state.wsMessageLimit; await refreshWebSocketMessages(); return; }
    if (event.target.closest('#ws-send-button')) { await sendWebSocketMessage(); return; }
    const wsConnection = event.target.closest('[data-ws-connection]');
    if (wsConnection) { await selectWebSocketConnection(wsConnection.dataset.wsConnection); return; }
    const wsMessage = event.target.closest('[data-ws-message]');
    if (wsMessage) { await openWebSocketMessage(wsMessage.dataset.wsMessage); return; }
    if (event.target.closest('#finding-status-save')) { await saveFindingStatus(event.target.closest('#finding-status-save').dataset.findingStatusId); return; }
    if (event.target.closest('#repeater-send')) { await sendRepeater(); return; }
    if (event.target.closest('#copy-response')) { try { await copyText($('#repeater-response').textContent); showToast('Response copied.'); } catch (e) { showToast(e.message, 'error'); } return; }
    const sitemap = event.target.closest('[data-sitemap-id]');
    if (sitemap) { await openSiteMapEntry(sitemap.dataset.sitemapId); return; }
    const finding = event.target.closest('[data-finding-id]');
    if (finding) { await openFinding(finding.dataset.findingId); return; }
    const pending = event.target.closest('[data-pending-id]');
    if (pending) { state.selectedPending = pending.dataset.pendingId; $('#pending-request-editor').dataset.dirty = ''; renderPendingRows(); return; }
    const historyRow = event.target.closest('[data-history-id]');
    if (historyRow) { await openHistoryDetail(historyRow.dataset.historyId); return; }
    const action = event.target.closest('[data-action]');
    if (action) {
      if (action.dataset.action === 'use-repeater') await useInRepeater(action.dataset.id);
      if (action.dataset.action === 'copy-raw') await copyHistoryRequest(action.dataset.id);
      if (action.dataset.action === 'inspect-capture') await goToHistory(action.dataset.id);
      if (action.dataset.action === 'finding-history') await goToHistory(action.dataset.id);
      return;
    }
    const deleteRuleButton = event.target.closest('[data-delete-rule]');
    if (deleteRuleButton) { await deleteScope(deleteRuleButton.dataset.deleteRule); return; }
    if (event.target.closest('#save-port')) {
      const port = Number($('#proxy-port').value);
      if (!Number.isInteger(port) || port < 1 || port > 65535) { showToast('Port must be between 1 and 65535.', 'error'); return; }
      state.port = port; $('#listener-summary').textContent = `127.0.0.1:${port}`; $('#proxy-endpoint').textContent = `http://127.0.0.1:${port}`; showToast(`Port set to ${port}; restart the proxy to apply it.`); return;
    }
  });

  $('#intercept-toggle').addEventListener('change', event => toggleIntercept(event.target.checked));
  $('#pending-request-editor').addEventListener('input', () => { $('#pending-request-editor').dataset.dirty = 'true'; });
  $('#history-search').addEventListener('input', () => {
    window.clearTimeout(state.searchTimer);
    state.searchTimer = window.setTimeout(refreshHistory, 220);
  });
  $('#sitemap-search').addEventListener('input', () => { window.clearTimeout(state.toolSearchTimer); state.toolSearchTimer = window.setTimeout(refreshSiteMap, 220); });
  $('#sitemap-host').addEventListener('input', () => { window.clearTimeout(state.toolSearchTimer); state.toolSearchTimer = window.setTimeout(refreshSiteMap, 220); });
  $('#sitemap-method').addEventListener('change', refreshSiteMap);
  $('#sitemap-type').addEventListener('change', refreshSiteMap);
  $('#sitemap-status').addEventListener('change', refreshSiteMap);
  $('#sitemap-scope').addEventListener('change', refreshSiteMap);
  $('#findings-search').addEventListener('input', () => { window.clearTimeout(state.toolSearchTimer); state.toolSearchTimer = window.setTimeout(refreshFindings, 220); });
  $('#findings-severity').addEventListener('change', refreshFindings);
  $('#findings-status').addEventListener('change', refreshFindings);
  $('#decoder-input').addEventListener('input', updateDecoderCounts);
  $('#decoder-output').addEventListener('input', updateDecoderCounts);
  $('#compare-mode').addEventListener('change', invalidateCompareResult);
  $('#compare-left').addEventListener('input', invalidateCompareResult);
  $('#compare-right').addEventListener('input', invalidateCompareResult);
  $('#ws-connection-search').addEventListener('input', () => { window.clearTimeout(state.toolSearchTimer); state.wsConnectionOffset = 0; state.toolSearchTimer = window.setTimeout(refreshWebSocketConnections, 220); });
  $('#ws-connection-state').addEventListener('change', () => { state.wsConnectionOffset = 0; refreshWebSocketConnections(); });
  $('#ws-message-search').addEventListener('input', () => { window.clearTimeout(state.toolSearchTimer); state.wsMessageOffset = 0; state.toolSearchTimer = window.setTimeout(() => refreshWebSocketMessages(true), 220); });
  $('#ws-message-direction').addEventListener('change', () => refreshWebSocketMessages(true));
  $('#ws-message-opcode').addEventListener('change', () => refreshWebSocketMessages(true));
  document.addEventListener('change', event => {
    if (event.target.id === 'ws-payload-format') renderWebSocketPayload();
    if (event.target.id === 'ws-send-format') { const editor = $('#ws-send-editor'); if (editor) editor.placeholder = event.target.value === 'binary' ? 'Paste Base64 bytes to send as a binary message…' : 'Enter UTF-8 text to send…'; }
  });
  $('#repeater-request').addEventListener('input', updateRequestSize);
  $('#scope-form').addEventListener('submit', addScope);
  document.addEventListener('keydown', event => {
    if (event.ctrlKey && !event.shiftKey && !event.altKey && event.key.toLowerCase() === 'k') {
      event.preventDefault(); switchView('history'); $('#history-search').focus(); return;
    }
    if (event.ctrlKey && !event.shiftKey && !event.altKey && ['1', '2', '3', '4', '5', '6', '7', '8'].includes(event.key)) {
      event.preventDefault(); switchView(({ '1': 'proxy', '2': 'history', '3': 'repeater', '4': 'sitemap', '5': 'findings', '6': 'decoder', '7': 'comparer', '8': 'websockets' })[event.key]);
    }
    if (event.key === 'Escape' && document.activeElement === $('#history-search')) { $('#history-search').value = ''; refreshHistory(); $('#history-search').blur(); }
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && state.view === 'repeater') { event.preventDefault(); sendRepeater(); }
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && state.view === 'websockets') { event.preventDefault(); sendWebSocketMessage(); }
  });

  async function init() {
    try {
      const session = await fetch('/api/session', { cache: 'no-store' }).then(r => r.json());
      state.token = session.token;
      await refreshStatus(false);
      await refreshHistory();
      await refreshScope();
      populateCompareSources();
      updateRequestSize();
      await refreshPending();
      window.setInterval(async () => {
        await refreshStatus();
        if (state.view === 'proxy') await refreshPending();
        else if (state.view === 'history') await refreshHistory();
        else if (state.view === 'findings') await refreshFindings();
        else if (state.view === 'websockets') await refreshWebSocketConnections();
      }, 1800);
    } catch (error) { showToast(`Could not initialize the local app: ${error.message}`, 'error'); }
  }
  init();
})();
