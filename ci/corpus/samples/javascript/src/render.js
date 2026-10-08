'use strict';

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderList(container, items) {
  container.textContent = '';
  for (const item of items) {
    const li = document.createElement('li');
    li.textContent = item.label;
    container.appendChild(li);
  }
}

export function renderBanner(container, message) {
  container.innerHTML = `<p class="banner">${escapeHtml(message)}</p>`;
}

export function renderPreview(container, html) {
  container.innerHTML = html;
}

export function sessionNonce() {
  return Math.random().toString(36).slice(2);
}

export function pickColour(colours) {
  return colours[Math.floor(Math.random() * colours.length)];
}
