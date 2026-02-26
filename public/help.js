const helpDoc = document.getElementById('helpDoc');
const reloadHelpBtn = document.getElementById('reloadHelpBtn');

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function inlineMarkdown(text) {
  const escaped = escapeHtml(text);
  return escaped
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>');
}

function plainHeadingText(text) {
  return String(text || '')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .trim();
}

function slugifyHeading(text) {
  const base = plainHeadingText(text)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return base || 'section';
}

function renderMarkdown(markdown) {
  const lines = String(markdown || '').split('\n');
  const html = [];
  let inList = false;
  let inCode = false;
  let codeLines = [];
  const usedHeadingIds = new Map();

  const closeList = () => {
    if (inList) {
      html.push('</ul>');
      inList = false;
    }
  };

  const closeCode = () => {
    if (inCode) {
      html.push(`<pre><code>${escapeHtml(codeLines.join('\n'))}</code></pre>`);
      inCode = false;
      codeLines = [];
    }
  };

  const buildHeadingId = (rawHeading) => {
    const match = String(rawHeading || '').match(/^(.*?)\s*\{#([a-zA-Z0-9_-]+)\}\s*$/);
    const headingText = match ? String(match[1] || '').trim() : String(rawHeading || '').trim();
    const requested = match ? String(match[2] || '').trim() : '';
    const baseId = requested || slugifyHeading(headingText);
    const count = Number(usedHeadingIds.get(baseId) || 0) + 1;
    usedHeadingIds.set(baseId, count);
    const id = count > 1 ? `${baseId}-${count}` : baseId;
    return { id, headingText };
  };

  for (const raw of lines) {
    const line = raw.replace(/\r$/, '');
    if (line.trim().startsWith('```')) {
      if (inCode) {
        closeCode();
      } else {
        closeList();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      codeLines.push(line);
      continue;
    }

    if (!line.trim()) {
      closeList();
      html.push('<div class="help-gap"></div>');
      continue;
    }

    const h1 = line.match(/^#\s+(.+)$/);
    if (h1) {
      closeList();
      const heading = buildHeadingId(h1[1]);
      html.push(`<h1 id="${escapeHtml(heading.id)}">${inlineMarkdown(heading.headingText)}</h1>`);
      continue;
    }
    const h2 = line.match(/^##\s+(.+)$/);
    if (h2) {
      closeList();
      const heading = buildHeadingId(h2[1]);
      html.push(`<h2 id="${escapeHtml(heading.id)}">${inlineMarkdown(heading.headingText)}</h2>`);
      continue;
    }
    const h3 = line.match(/^###\s+(.+)$/);
    if (h3) {
      closeList();
      const heading = buildHeadingId(h3[1]);
      html.push(`<h3 id="${escapeHtml(heading.id)}">${inlineMarkdown(heading.headingText)}</h3>`);
      continue;
    }

    const listItem = line.match(/^\s*-\s+(.+)$/);
    if (listItem) {
      if (!inList) {
        html.push('<ul>');
        inList = true;
      }
      html.push(`<li>${inlineMarkdown(listItem[1])}</li>`);
      continue;
    }

    closeList();
    html.push(`<p>${inlineMarkdown(line)}</p>`);
  }

  closeList();
  closeCode();
  return html.join('\n');
}

function focusHelpAnchor() {
  const hash = decodeURIComponent(String(window.location.hash || '').replace(/^#/, '').trim());
  if (!hash || !helpDoc) return;
  const target = document.getElementById(hash);
  if (!target || !helpDoc.contains(target)) return;
  target.scrollIntoView({ block: 'start', behavior: 'smooth' });
  target.classList.add('help-anchor-focus');
  window.setTimeout(() => target.classList.remove('help-anchor-focus'), 1800);
}

function injectReturnToTerminalButton() {
  if (!helpDoc) return;
  const existing = helpDoc.querySelector('.help-return-terminal-wrap');
  if (existing) existing.remove();
  const toolsHeading = helpDoc.querySelector('#tools-terminal');
  if (!toolsHeading) return;

  const wrap = document.createElement('div');
  wrap.className = 'help-return-terminal-wrap';

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'ghost-btn help-return-terminal-btn';
  button.textContent = 'Return to Terminal';
  button.addEventListener('click', () => {
    window.location.assign('/');
  });

  wrap.appendChild(button);
  toolsHeading.insertAdjacentElement('afterend', wrap);
}

async function getJson(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const payload = await res.json().catch(() => ({}));
    throw new Error(payload.error || `Request failed: ${res.status}`);
  }
  return res.json();
}

async function loadHelp() {
  if (!helpDoc) return;
  helpDoc.innerHTML = '<p>Loading help content...</p>';
  try {
    const payload = await getJson('/api/help/readme');
    helpDoc.innerHTML = renderMarkdown(payload.content || 'No help content available.');
    injectReturnToTerminalButton();
    focusHelpAnchor();
  } catch (err) {
    helpDoc.innerHTML = `<p>${escapeHtml(err.message)}</p>`;
  }
}

reloadHelpBtn?.addEventListener('click', () => {
  loadHelp().catch(() => {});
});

window.addEventListener('hashchange', () => {
  focusHelpAnchor();
});

loadHelp().catch(() => {});
