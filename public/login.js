const loginForm = document.getElementById('loginForm');
const loginMsg = document.getElementById('loginMsg');
const registerBtn = document.getElementById('registerBtn');
const registerDialog = document.getElementById('registerDialog');
const registerForm = document.getElementById('registerForm');
const registerMsg = document.getElementById('registerMsg');
const registerUsername = document.getElementById('registerUsername');
const registerPasswordWrap = document.getElementById('registerPasswordWrap');
const registerPassword = document.getElementById('registerPassword');
const registerPasswordReq = document.getElementById('registerPasswordReq');
const registerTotpWrap = document.getElementById('registerTotpWrap');
const registerTotp = document.getElementById('registerTotp');
const registerQrWrap = document.getElementById('registerQrWrap');
const registerQrImage = document.getElementById('registerQrImage');
const registerSecret = document.getElementById('registerSecret');
const registerSubmit = document.getElementById('registerSubmit');
const registerCancel = document.getElementById('registerCancel');
const loginPanel = document.querySelector('.login-panel');

let registerSetupToken = '';
let registerStage = 'username';
let loginRefreshPulseTimer = null;
let loginRefreshPulseCleanupTimer = null;

if (registerForm) registerForm.noValidate = true;

function setRegisterElementVisible(node, visible, displayValue = '') {
  if (!node) return;
  node.hidden = !visible;
  if (visible) {
    if (displayValue) {
      node.style.display = displayValue;
    } else {
      node.style.removeProperty('display');
    }
  } else {
    node.style.display = 'none';
  }
}

function hideRegisterTotpInfo() {
  setRegisterElementVisible(registerTotpWrap, false);
  setRegisterElementVisible(registerQrWrap, false);
  if (registerTotp) {
    registerTotp.required = false;
    registerTotp.value = '';
  }
  if (registerQrImage) registerQrImage.src = '';
  if (registerSecret) registerSecret.textContent = '';
}

function ensureLoginTotpField() {
  if (!loginForm) return null;
  let wrap = document.getElementById('loginTotpWrap');
  let input = document.getElementById('loginTotp');
  if (wrap && input) return input;
  wrap = document.createElement('label');
  wrap.id = 'loginTotpWrap';
  wrap.textContent = 'TOTP Code ';
  input = document.createElement('input');
  input.id = 'loginTotp';
  input.name = 'totp';
  input.inputMode = 'numeric';
  input.maxLength = 6;
  input.placeholder = '123456';
  wrap.appendChild(input);
  const submitBtn = loginForm.querySelector('button[type="submit"]');
  if (submitBtn?.parentNode) {
    submitBtn.parentNode.insertBefore(wrap, submitBtn);
  } else {
    loginForm.appendChild(wrap);
  }
  return input;
}

function removeLoginTotpField() {
  const wrap = document.getElementById('loginTotpWrap');
  if (wrap) wrap.remove();
}

async function getJson(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const payload = await res.json().catch(() => ({}));
    throw new Error(payload.error || `Request failed: ${res.status}`);
  }
  return res.json();
}

function triggerLoginRefreshPulse() {
  if (!loginPanel) return;
  if (loginRefreshPulseCleanupTimer) clearTimeout(loginRefreshPulseCleanupTimer);
  loginPanel.classList.remove('global-refresh-pulse');
  void loginPanel.offsetWidth;
  loginPanel.classList.add('global-refresh-pulse');
  loginRefreshPulseCleanupTimer = setTimeout(() => {
    loginPanel.classList.remove('global-refresh-pulse');
  }, 1650);
  loginPanel.addEventListener('animationend', () => {
    loginPanel.classList.remove('global-refresh-pulse');
  }, { once: true });
}

function startLoginRefreshPulse(refreshMs) {
  if (loginRefreshPulseTimer) clearTimeout(loginRefreshPulseTimer);
  const cadenceMs = Math.max(1000, Number(refreshMs) || 60000);
  const tick = () => {
    triggerLoginRefreshPulse();
    loginRefreshPulseTimer = setTimeout(tick, cadenceMs);
  };
  loginRefreshPulseTimer = setTimeout(tick, cadenceMs);
}

async function boot() {
  try {
    const state = await getJson('/api/auth/me');
    startLoginRefreshPulse(state?.runtime?.globalDataRefreshMs);
  } catch {
    startLoginRefreshPulse(60000);
  }
}

function resetRegisterDialog() {
  registerSetupToken = '';
  registerStage = 'username';
  if (registerMsg) registerMsg.textContent = 'Enter your assigned username to continue setup.';
  setRegisterElementVisible(registerPasswordWrap, false);
  setRegisterElementVisible(registerPasswordReq, true);
  hideRegisterTotpInfo();
  if (registerPassword) {
    registerPassword.value = '';
    registerPassword.required = false;
    registerPassword.disabled = true;
  }
  if (registerSubmit) registerSubmit.textContent = 'Continue';
}

function openRegisterDialog(prefillUsername = '') {
  if (!registerDialog) return;
  resetRegisterDialog();
  if (registerUsername) registerUsername.value = String(prefillUsername || '').trim().toLowerCase();
  if (typeof registerDialog.showModal === 'function') {
    registerDialog.showModal();
  }
}

loginForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(loginForm);
  const username = String(formData.get('username') || '').trim().toLowerCase();
  const password = String(formData.get('password') || '');
  const totp = String(formData.get('totp') || '').trim();
  if (!username || !password) return;
  if (loginMsg) loginMsg.textContent = 'Signing in...';

  try {
    const result = await getJson('/api/auth/local/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, totp })
    });
    if (result?.next === 'verify_totp') {
      const loginTotp = ensureLoginTotpField();
      if (loginTotp) {
        loginTotp.required = true;
        loginTotp.focus();
      }
      if (loginMsg) loginMsg.textContent = 'Enter your TOTP code to complete sign-in.';
      return;
    }
    if (result?.next === 'set_password' && result?.setupToken) {
      if (loginMsg) loginMsg.textContent = 'Additional setup required. Continue in the setup dialog.';
      openRegisterDialog(username);
      registerSetupToken = String(result.setupToken);
      registerStage = 'password';
      setRegisterElementVisible(registerPasswordWrap, true, 'grid');
      setRegisterElementVisible(registerPasswordReq, true);
      hideRegisterTotpInfo();
      if (registerPassword) {
        registerPassword.required = true;
        registerPassword.disabled = false;
      }
      if (registerSubmit) registerSubmit.textContent = 'Set Password';
      if (registerMsg) registerMsg.textContent = 'Create your password to complete setup.';
      return;
    }
    if (result?.next === 'enroll_totp' && result?.setupToken) {
      removeLoginTotpField();
      openRegisterDialog(username);
      registerSetupToken = String(result.setupToken);
      registerStage = 'totp';
      setRegisterElementVisible(registerTotpWrap, true, 'grid');
      setRegisterElementVisible(registerPasswordWrap, false);
      setRegisterElementVisible(registerPasswordReq, false);
      if (registerPassword) {
        registerPassword.required = false;
        registerPassword.value = '';
        registerPassword.disabled = true;
      }
      if (registerTotp) {
        registerTotp.required = true;
        registerTotp.focus();
      }
      setRegisterElementVisible(registerQrWrap, true, 'grid');
      if (registerQrImage) registerQrImage.src = result.qrUrl || '';
      if (registerSecret) registerSecret.textContent = result.secret || '';
      if (registerSubmit) registerSubmit.textContent = 'Verify TOTP';
      if (registerMsg) registerMsg.textContent = 'Scan the QR code in your authenticator app, then enter the 6-digit code.';
      return;
    }
    removeLoginTotpField();
    window.location.replace('/');
  } catch (err) {
    if (loginMsg) loginMsg.textContent = err.message;
  }
});

registerBtn?.addEventListener('click', () => {
  const prefill = document.getElementById('username')?.value || '';
  openRegisterDialog(prefill);
});

registerCancel?.addEventListener('click', () => {
  registerDialog?.close();
  resetRegisterDialog();
});

registerDialog?.addEventListener('close', () => {
  resetRegisterDialog();
});

registerQrImage?.addEventListener('error', () => {
  // Only show the error when the QR image is actually visible (TOTP enrollment stage)
  if (registerQrWrap && !registerQrWrap.hidden && registerQrImage?.src) {
    if (registerMsg) {
      registerMsg.textContent = 'Unable to render QR image. Check server logs and try again.';
    }
  }
});

registerForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const username = String(registerUsername?.value || '').trim().toLowerCase();
  if (!username) return;

  if (registerSubmit) registerSubmit.disabled = true;
  try {
    if (registerStage === 'username') {
      if (registerMsg) registerMsg.textContent = 'Checking user...';
      const result = await getJson('/api/auth/local/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password: '' })
      });
      if (result?.next !== 'set_password' || !result?.setupToken) {
        if (registerMsg) registerMsg.textContent = 'Registration could not be started. Contact your administrator.';
        return;
      }
      registerSetupToken = String(result.setupToken);
      registerStage = 'password';
      setRegisterElementVisible(registerPasswordWrap, true, 'grid');
      setRegisterElementVisible(registerPasswordReq, true);
      hideRegisterTotpInfo();
      if (registerPassword) {
        registerPassword.required = true;
        registerPassword.disabled = false;
        registerPassword.focus();
      }
      if (registerSubmit) registerSubmit.textContent = 'Set Password';
      if (registerMsg) registerMsg.textContent = 'Create your password to complete setup.';
      return;
    }

    if (registerStage === 'password') {
      const newPassword = String(registerPassword?.value || '');
      if (newPassword.length < 10) {
        if (registerMsg) registerMsg.textContent = 'Password must be at least 10 characters.';
        return;
      }
      if (registerMsg) registerMsg.textContent = 'Saving password...';
      const setupResult = await getJson('/api/auth/local/setup-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ setupToken: registerSetupToken, password: newPassword })
      });
      if (setupResult?.next === 'enroll_totp' && setupResult?.setupToken) {
        registerSetupToken = String(setupResult.setupToken);
        registerStage = 'totp';
        setRegisterElementVisible(registerPasswordWrap, false);
        setRegisterElementVisible(registerPasswordReq, false);
        if (registerPassword) {
          registerPassword.required = false;
          registerPassword.value = '';
          registerPassword.disabled = true;
        }
        setRegisterElementVisible(registerTotpWrap, true, 'grid');
        if (registerTotp) {
          registerTotp.required = true;
          registerTotp.focus();
        }
        setRegisterElementVisible(registerQrWrap, true, 'grid');
        if (registerQrImage) registerQrImage.src = setupResult.qrUrl || '';
        if (registerSecret) registerSecret.textContent = setupResult.secret || '';
        if (registerSubmit) registerSubmit.textContent = 'Verify TOTP';
        if (registerMsg) registerMsg.textContent = 'Scan the QR code in your authenticator app, then enter the 6-digit code.';
        return;
      }
      if (setupResult?.ok) {
        if (loginMsg) loginMsg.textContent = 'Password set. Logging in...';
        window.location.replace('/');
      }
      return;
    }

    if (registerStage === 'totp') {
      const totpCode = String(registerTotp?.value || '').trim();
      if (!/^\d{6}$/.test(totpCode)) {
        if (registerMsg) registerMsg.textContent = 'Enter a valid 6-digit TOTP code.';
        return;
      }
      if (registerMsg) registerMsg.textContent = 'Verifying TOTP...';
      await getJson('/api/auth/local/verify-totp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ setupToken: registerSetupToken, totp: totpCode })
      });
      if (loginMsg) loginMsg.textContent = 'Registration complete. Signed in.';
      registerDialog?.close();
      removeLoginTotpField();
      window.location.replace('/');
      return;
    }
  } catch (err) {
    if (registerMsg) {
      if (registerStage === 'username') {
        registerMsg.textContent = 'Registration could not be started. Contact your administrator.';
      } else if (registerStage === 'password') {
        registerMsg.textContent = 'Unable to complete setup. Verify password requirements or contact your administrator.';
      } else {
        registerMsg.textContent = 'Unable to verify TOTP code. Check your authenticator app and try again.';
      }
    }
  } finally {
    if (registerSubmit) registerSubmit.disabled = false;
  }
});

boot();
