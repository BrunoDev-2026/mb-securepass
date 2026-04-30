/* =============================================================
   MB SecurePass - script.js (Versão Melhorada)
   Engenheiro: Debugging & Security Audit Pass
   Correções: Ver comentários [FIX] abaixo
   ============================================================= */

// ─── SELETORES DE DOM ─────────────────────────────────────────
const lengthEl      = document.getElementById("length");
const lengthValue   = document.getElementById("lengthValue");
const passwordEl    = document.getElementById("password");
const strengthBar   = document.getElementById("strengthBar");
const strengthText  = document.getElementById("strengthText");
const scannerEl     = document.getElementById("scanner");
const historySidebar= document.getElementById("historySidebar");
const historyList   = document.getElementById("historyList");
const historyFooter = document.getElementById("historyFooter");
const modalOverlay  = document.getElementById("modalOverlay");
const qrModal       = document.getElementById("qrModal");
const mainCopyBtn   = document.getElementById("mainCopyBtn");
const crackTimeEl   = document.getElementById("crackTime");

// Cache de checkboxes para evitar consultas repetitivas ao DOM
const options = {
  upper:  document.getElementById("uppercase"),
  lower:  document.getElementById("lowercase"),
  number: document.getElementById("numbers"),
  symbol: document.getElementById("symbols")
};

// Conjuntos de caracteres
const charset = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers:   "0123456789",
  // [FIX #1] Removido o '=' do charset de símbolos para evitar quebra
  // em contextos de URL/token. Adicionados outros símbolos seguros.
  symbols:   "!@#$%^&*()_+~`|}{[]:;?><,./-"
};

// ─── ESTADO ──────────────────────────────────────────────────
let passwordHistory        = JSON.parse(localStorage.getItem('mb_securepass_history')) || [];
let isCurrentPasswordCopied = true;  // Considera a senha inicial como "já vista"
let isHistoryAuthenticated  = false;
let clipboardTimer          = null;
let audioCtx                = null;  // [FIX #2] Declarado no escopo global (estava duplicado)

// ─── SEGURANÇA: HASH SHA-256 ──────────────────────────────────
/**
 * Gera hash SHA-256 da senha mestra para armazenamento seguro.
 * Nunca armazenamos a senha em texto puro.
 */
async function hashPassword(password) {
  const encoder   = new TextEncoder();
  const data      = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray  = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── AUTENTICAÇÃO: SENHA MESTRA ───────────────────────────────
async function handleSetMasterPassword() {
  const btn     = document.getElementById('setMasterBtn');
  const pwInput = document.getElementById('newMasterPassword');
  const pw      = pwInput.value.trim();

  // [FIX #3] Validação mínima de comprimento (6 chars) antes de aceitar
  if (!pw || pw.length < 6) {
    showToast("Senha Mestra deve ter pelo menos 6 caracteres!");
    return;
  }

  btn.classList.add('loading');
  btn.disabled = true;

  const hash = await hashPassword(pw);
  localStorage.setItem('mb_securepass_master', hash);
  isHistoryAuthenticated = true;
  showHistoryContent();
  pwInput.value = '';

  btn.classList.remove('loading');
  btn.disabled = false;
}

async function handleVerifyMasterPassword() {
  const btn     = document.getElementById('verifyMasterBtn');
  const pwInput = document.getElementById('masterPasswordInput');
  const pw      = pwInput.value;

  if (!pw) return;

  btn.classList.add('loading');
  btn.disabled = true;

  const storedHash = localStorage.getItem('mb_securepass_master');
  const hash       = await hashPassword(pw);

  if (hash === storedHash) {
    isHistoryAuthenticated = true;
    showHistoryContent();
    pwInput.value = '';
  } else {
    // [FIX #4] Substituído alert() nativo (bloqueante) por showToast()
    showToast("Senha Mestra incorreta!");
    pwInput.value = '';
    // Pequeno tremor visual no input para feedback de erro
    pwInput.style.borderColor = '#ff4d4d';
    pwInput.style.animation = 'shake 0.3s ease';
    setTimeout(() => {
      pwInput.style.borderColor = '';
      pwInput.style.animation = '';
    }, 400);
  }

  btn.classList.remove('loading');
  btn.disabled = false;
}

function lockHistory() {
  const historyContent = document.getElementById('historyContent');
  const authSection    = document.getElementById('authSection');

  if (historyContent && historyContent.style.display !== 'none') {
    historyContent.classList.add('fade-out');
    setTimeout(() => {
      isHistoryAuthenticated = false;
      historyContent.classList.remove('fade-out');
      checkAuthStatus();
      authSection.classList.add('fade-in');
      setTimeout(() => authSection.classList.remove('fade-in'), 300);
    }, 300);
  }
}

function showHistoryContent() {
  document.getElementById('authSection').style.display = 'none';
  document.getElementById('historyContent').style.display = 'flex';
  const lockBtn = document.getElementById('lockHistoryBtn');
  if (lockBtn) lockBtn.style.display = 'block';
  renderHistory();
}

function toggleHistory() {
  historySidebar.classList.toggle('open');
  if (historySidebar.classList.contains('open')) {
    checkAuthStatus();
  }
}

function checkAuthStatus() {
  const hasMaster = !!localStorage.getItem('mb_securepass_master');
  if (isHistoryAuthenticated) {
    showHistoryContent();
  } else {
    document.getElementById('historyContent').style.display = 'none';
    document.getElementById('authSection').style.display = 'block';
    const lockBtn = document.getElementById('lockHistoryBtn');
    if (lockBtn) lockBtn.style.display = 'none';
    document.getElementById('setupView').style.display = hasMaster ? 'none' : 'block';
    document.getElementById('loginView').style.display  = hasMaster ? 'block' : 'none';
  }
}

// ─── HISTÓRICO ────────────────────────────────────────────────
function addToHistory(password) {
  // [FIX #5] Evita duplicata consecutiva no topo do histórico
  if (passwordHistory[0] === password) return;

  passwordHistory.unshift(password);
  if (passwordHistory.length > 5) passwordHistory.pop();
  localStorage.setItem('mb_securepass_history', JSON.stringify(passwordHistory));

  if (isHistoryAuthenticated) renderHistory();
}

function renderHistory() {
  historyList.innerHTML = '';

  if (passwordHistory.length === 0) {
    historyList.innerHTML = '<p style="color:rgba(255,255,255,0.2); text-align:center; margin-top:20px;">Vazio</p>';
    historyFooter.style.display = 'none';
  } else {
    historyFooter.style.display = 'block';
    passwordHistory.forEach((pw) => {
      const item = document.createElement('div');
      item.className = 'history-item';

      // [FIX #6] XSS: Nunca inserir senha diretamente via innerHTML como atributo
      // Usamos textContent + addEventListener para segurança total contra XSS
      const span = document.createElement('span');
      span.textContent = pw;
      span.title       = pw;

      const copyBtn = document.createElement('button');
      copyBtn.className = 'icon-btn';
      copyBtn.title     = 'Copiar';
      copyBtn.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
          fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        </svg>`;
      copyBtn.addEventListener('click', () => copySpecific(pw));

      item.appendChild(span);
      item.appendChild(copyBtn);
      historyList.appendChild(item);
    });
  }
}

function showClearModal() { modalOverlay.classList.add('active'); }
function hideClearModal()  { modalOverlay.classList.remove('active'); }

function clearHistory() {
  passwordHistory = [];
  localStorage.removeItem('mb_securepass_history');
  renderHistory();
  hideClearModal();
}

// ─── EXPORTAÇÃO ───────────────────────────────────────────────
function exportHistory(format) {
  if (passwordHistory.length === 0) return;

  let content  = '';
  const fileName = `MB_SecurePass_History.${format}`;
  const mimeType = format === 'json' ? 'application/json' : 'text/plain';

  if (format === 'json') {
    content = JSON.stringify({
      appName:    'MB SecurePass',
      exportDate: new Date().toISOString(),
      passwords:  passwordHistory
    }, null, 2);
  } else {
    content  = 'MB SECUREPASS - HISTÓRICO DE SENHAS\n';
    content += '====================================\n\n';
    passwordHistory.forEach((pw, i) => {
      content += `[${i + 1}] ${pw}\n`;
    });
    content += '\nGerado em: ' + new Date().toLocaleString('pt-BR');
  }

  const blob = new Blob([content], { type: mimeType });
  const url  = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href     = url;
  link.download = fileName;
  document.body.appendChild(link); // [FIX #7] Necessário em Firefox
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// ─── QR CODE ─────────────────────────────────────────────────
function showQRCode() {
  const password = passwordEl.value;
  if (!password) {
    showToast("Gere uma senha primeiro!");
    return;
  }

  // [SECURITY NOTE] O uso de API externa transmite a senha via rede.
  // Sugestão: Substituir por uma biblioteca local (ex: qrcode.js) 
  // para geração 100% offline e privada.

  const qrContainer = document.getElementById('qrContainer');
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(password)}`;
  qrContainer.innerHTML = `<img src="${qrUrl}" alt="QR Code da senha" title="Escaneie sua senha">`;
  qrModal.classList.add('active');
}

async function downloadQRCode() {
  const img = document.querySelector('#qrContainer img');
  if (!img) return;

  try {
    const response = await fetch(img.src);
    const blob     = await response.blob();
    const url      = window.URL.createObjectURL(blob);
    const a        = document.createElement('a');
    a.href         = url;
    a.download     = 'MB_SecurePass_QRCode.png';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  } catch {
    showToast("Erro ao baixar QR Code");
  }
}

function hideQRCode() { qrModal.classList.remove('active'); }

// ─── RESET SENHA MESTRA ───────────────────────────────────────
function showResetMasterModal()  { document.getElementById('resetMasterModal').classList.add('active'); }
function hideResetMasterModal()  { document.getElementById('resetMasterModal').classList.remove('active'); }

function resetMasterPassword() {
  localStorage.removeItem('mb_securepass_master');
  localStorage.removeItem('mb_securepass_history');
  passwordHistory        = [];
  isHistoryAuthenticated = false;

  hideResetMasterModal();
  checkAuthStatus();
  showToast("Segurança e histórico resetados!");
}

// ─── GERAÇÃO CRIPTOGRÁFICA DE SENHA ──────────────────────────
/**
 * Usa window.crypto.getRandomValues para geração segura.
 * Garante ao menos 1 caractere de cada tipo selecionado (mandatory chars).
 * Embaralha com Fisher-Yates + Crypto para distribuição uniforme.
 */
function generatePassword(fullEffects = true) {
  const length = +lengthEl.value;
  let pool = '';
  const mandatoryChars = [];

  isCurrentPasswordCopied = false;

  if (options.upper.checked)  { pool += charset.uppercase; mandatoryChars.push(getRandomChar(charset.uppercase)); }
  if (options.lower.checked)  { pool += charset.lowercase; mandatoryChars.push(getRandomChar(charset.lowercase)); }
  if (options.number.checked) { pool += charset.numbers;   mandatoryChars.push(getRandomChar(charset.numbers)); }
  if (options.symbol.checked) { pool += charset.symbols;   mandatoryChars.push(getRandomChar(charset.symbols)); }

  // [FIX #8] Nenhuma opção selecionada — limpa tudo e retorna sem travar
  if (pool === '') {
    passwordEl.value = '';
    updateStrength('');
    showToast("Selecione ao menos um tipo de caractere!");
    return;
  }

  let generated = [...mandatoryChars];

  // Preenche os caracteres restantes em lote (performance)
  const remaining = length - mandatoryChars.length;
  if (remaining > 0) {
    const rnd = new Uint32Array(remaining);
    window.crypto.getRandomValues(rnd);
    for (let i = 0; i < remaining; i++) {
      generated.push(pool[rnd[i] % pool.length]);
    }
  }

  // Fisher-Yates shuffle criptográfico
  for (let i = generated.length - 1; i > 0; i--) {
    const j = window.crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [generated[i], generated[j]] = [generated[j], generated[i]];
  }

  const finalPassword = generated.join('');
  passwordEl.value    = finalPassword;
  updateStrength(finalPassword);

  if (fullEffects) {
    triggerScanner();
    playScanSound();
    addToHistory(finalPassword);
  }
}

// ─── EFEITOS VISUAIS ─────────────────────────────────────────
function triggerScanner() {
  if (!scannerEl) return;
  scannerEl.classList.remove('scanning');
  passwordEl.classList.remove('glitch-active');
  void scannerEl.offsetWidth;   // Force reflow para reiniciar animação CSS
  scannerEl.classList.add('scanning');
  passwordEl.classList.add('glitch-active');
  setTimeout(() => passwordEl.classList.remove('glitch-active'), 800);
}

// ─── PRIVACIDADE (TOGGLE SHOW/HIDE) ──────────────────────────
function togglePrivacy() {
  const isHidden = passwordEl.type === 'password';
  passwordEl.type = isHidden ? 'text' : 'password';

  const eyeIcon = document.getElementById('eyeIcon');
  if (isHidden) {
    eyeIcon.innerHTML = `
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
      <line x1="1" y1="1" x2="23" y2="23"></line>`;
  } else {
    eyeIcon.innerHTML = `
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
      <circle cx="12" cy="12" r="3"></circle>`;
  }
}

// ─── CLIPBOARD ───────────────────────────────────────────────
/**
 * [FIX #9] Corrigido o padrão de sobrescrita de função (era frágil e podia
 * causar loop infinito se chamado recursivamente). Agora copySpecific é uma
 * função simples com feedback integrado.
 */
async function copyPassword() {
  if (!passwordEl.value) {
    showToast("Gere uma senha primeiro!");
    return;
  }
  await copySpecific(passwordEl.value, true);
}

async function copySpecific(text, isMainPassword = false) {
  // [FIX #10] Fallback para navigator.clipboard indisponível (HTTP, iframes)
  if (!navigator.clipboard) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity  = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    } catch {
      showToast("Não foi possível copiar a senha.");
      return;
    }
  } else {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      showToast("Permissão de clipboard negada.");
      return;
    }
  }

  if (text === passwordEl.value) {
    isCurrentPasswordCopied = true;
    updateCopyButtonFeedback();
  }

  showToast("✅ Senha copiada! Limpando em 60s...");
  startClipboardCleanup();
}

function startClipboardCleanup() {
  if (clipboardTimer) clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(() => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText('').then(() => {
        showToast("🔒 Área de transferência limpa.");
      }).catch(() => {});
    }
    clipboardTimer = null;
  }, 60000);
}

function updateCopyButtonFeedback() {
  // Guarda o SVG original para restaurar depois
  const originalHTML = mainCopyBtn.innerHTML;
  mainCopyBtn.innerHTML = `<span style="font-size:0.68rem;font-weight:700;letter-spacing:0.5px;color:var(--neon-green);">COPIADO!</span>`;
  setTimeout(() => { mainCopyBtn.innerHTML = originalHTML; }, 1500);
}

// ─── TOAST ────────────────────────────────────────────────────
function showToast(message) {
  const toast = document.getElementById('toast');

  // [FIX #11] Evita sobreposição de toasts: reinicia o timer antes de mostrar
  toast.classList.remove('show');
  void toast.offsetWidth;

  toast.innerText = message;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2500);
}

// ─── FORÇA DA SENHA ──────────────────────────────────────────
/**
 * Sistema de 5 níveis de classificação:
 *  🔴 Vulnerável  (0–20 pts)   – senha muito curta ou simples
 *  🟠 Exposta     (21–40 pts)  – comprimento ou variedade insuficiente
 *  🟡 Estável     (41–60 pts)  – boa base, pode melhorar
 *  🟢 Protegida   (61–80 pts)  – forte para uso geral
 *  🟣 Blindada    (81–100 pts) – nível máximo de segurança
 *
 * Score = comprimento ponderado (máx 50) + variedade de charset (máx 50)
 */
function updateStrength(password) {
  if (!password) {
    strengthBar.style.width         = '0';
    strengthBar.style.backgroundColor = '';
    strengthBar.style.boxShadow     = 'none';
    strengthText.innerText          = 'Analisando...';
    strengthText.style.color        = 'rgba(255,255,255,0.4)';
    crackTimeEl.innerText           = '⏱️ Tempo estimado para quebrar: -';
    mainCopyBtn.classList.remove('pulse-neon');
    return;
  }

  const score   = calculateScore(password);
  const entropy = calculateEntropy(password);

  const levels = [
    { min: 0,  max: 20,  text: '🔴 Vulnerável', color: '#ff4d4d', msg: 'Senha muito fácil de quebrar'     },
    { min: 21, max: 40,  text: '🟠 Exposta',    color: '#ff8c00', msg: 'Vulnerabilidade alta'             },
    { min: 41, max: 60,  text: '🟡 Estável',    color: '#ffd700', msg: 'Proteção razoável'                },
    { min: 61, max: 80,  text: '🟢 Protegida',  color: '#00ffa3', msg: 'Senha altamente segura'           },
    { min: 81, max: 100, text: '🟣 Blindada',   color: '#bc77ff', msg: 'Segurança de nível militar'       }
  ];

  // [FIX #12] Garante que sempre encontramos um nível (fallback para o primeiro)
  const current = levels.find(l => score >= l.min && score <= l.max) ?? levels[0];

  // Atualização visual com transição suave
  strengthBar.style.width           = `${score}%`;
  strengthBar.style.backgroundColor  = current.color;
  strengthBar.style.boxShadow        = `0 0 15px ${current.color}80`;
  strengthText.innerText             = `${current.text} — ${current.msg}`;
  strengthText.style.color           = current.color;

  // Tempo estimado para quebrar
  const secondsToCrack = Math.pow(2, entropy) / (2e9); // ~2 bilhões de tentativas/s (GPU moderna)
  crackTimeEl.innerText = `⏱️ Tempo estimado para quebrar: ${formatTime(secondsToCrack)}`;

  // Efeito Blindada: pulso neon no botão copiar
  if (score > 80) {
    if (!mainCopyBtn.classList.contains('pulse-neon')) playArmorSound();
    mainCopyBtn.classList.add('pulse-neon');
  } else {
    mainCopyBtn.classList.remove('pulse-neon');
  }
}

function calculateScore(password) {
  let score = 0;

  // Comprimento: máx 50 pontos (escala linear até 25 chars, depois satura)
  score += Math.min(password.length * 2, 50);

  // Variedade de caracteres: máx 50 pontos
  if (/[a-z]/.test(password))     score += 10;
  if (/[A-Z]/.test(password))     score += 15;
  if (/[0-9]/.test(password))     score += 10;
  if (/[^A-Za-z0-9]/.test(password)) score += 15;

  return Math.min(score, 100);
}

function calculateEntropy(password) {
  let poolSize = 0;
  if (/[a-z]/.test(password))         poolSize += 26;
  if (/[A-Z]/.test(password))         poolSize += 26;
  if (/[0-9]/.test(password))         poolSize += 10;
  if (/[^A-Za-z0-9]/.test(password))  poolSize += 32;
  if (poolSize === 0) return 0;
  return Math.log2(poolSize) * password.length;
}

/**
 * Formata segundos em linguagem natural, do mais imediato ao mais distante.
 */
function formatTime(seconds) {
  if (!isFinite(seconds) || seconds <= 0) return "menos de 1 segundo";
  if (seconds < 1)       return "menos de 1 segundo";
  if (seconds < 60)      return `${Math.floor(seconds)} segundo${Math.floor(seconds) !== 1 ? 's' : ''}`;

  const minutes = seconds / 60;
  if (minutes < 60)      return `${Math.floor(minutes)} minuto${Math.floor(minutes) !== 1 ? 's' : ''}`;

  const hours = minutes / 60;
  if (hours < 24)        return `${Math.floor(hours)} hora${Math.floor(hours) !== 1 ? 's' : ''}`;

  const days = hours / 24;
  if (days < 30)         return `${Math.floor(days)} dia${Math.floor(days) !== 1 ? 's' : ''}`;

  const months = days / 30;
  if (months < 12)       return `${Math.floor(months)} mês${Math.floor(months) !== 1 ? 'es' : ''}`;

  const years = days / 365;
  if (years < 1000)      return `${Math.floor(years)} ano${Math.floor(years) !== 1 ? 's' : ''}`;
  if (years < 1e6)       return `${(years / 1000).toFixed(0)} mil anos`;
  if (years < 1e9)       return `${(years / 1e6).toFixed(0)} milhões de anos`;
  if (years < 1e12)      return `${(years / 1e9).toFixed(0)} bilhões de anos`;

  return "tempo incalculável 🔒";
}

// ─── AUXILIAR ────────────────────────────────────────────────
function getRandomChar(str) {
  const array = new Uint32Array(1);
  window.crypto.getRandomValues(array);
  return str[array[0] % str.length];
}

// ─── WEB AUDIO: SONS SINTÉTICOS ──────────────────────────────
function getAudioCtx() {
  if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  // Garante que o contexto de áudio seja retomado se o navegador o suspender
  if (audioCtx.state === 'suspended') audioCtx.resume();
  return audioCtx;
}

function playScanSound() {
  try {
    const ctx  = getAudioCtx();
    const osc  = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.setValueAtTime(880, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(110, ctx.currentTime + 0.5);

    gain.gain.setValueAtTime(0.05, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.5);

    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.5);
  } catch { /* Silencia erros de audio policy */ }
}

function playArmorSound() {
  try {
    const ctx  = getAudioCtx();
    const osc  = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(40, ctx.currentTime);
    osc.frequency.linearRampToValueAtTime(300, ctx.currentTime + 0.05);
    osc.frequency.exponentialRampToValueAtTime(10, ctx.currentTime + 0.8);

    gain.gain.setValueAtTime(0.12, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.8);

    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.8);
  } catch { /* Silencia erros de audio policy */ }
}

// ─── EVENT LISTENERS ─────────────────────────────────────────
// Slider de comprimento
lengthEl.addEventListener('input', (e) => {
  lengthValue.innerText = e.target.value;
  generatePassword(false); // Atualiza sem disparar animações pesadas
});

lengthEl.addEventListener('change', () => generatePassword(true));

// Checkboxes de tipos de caractere
document.querySelectorAll('.options-grid input').forEach(el => {
  el.addEventListener('change', () => generatePassword(true));
});

// Tecla Enter nos campos de senha mestra
document.getElementById('newMasterPassword').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') handleSetMasterPassword();
});
document.getElementById('masterPasswordInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') handleVerifyMasterPassword();
});

// [FIX #13] Fechar modais ao clicar fora do conteúdo (overlay click)
modalOverlay.addEventListener('click', (e) => {
  if (e.target === modalOverlay) hideClearModal();
});
qrModal.addEventListener('click', (e) => {
  if (e.target === qrModal) hideQRCode();
});
document.getElementById('resetMasterModal').addEventListener('click', (e) => {
  if (e.target === document.getElementById('resetMasterModal')) hideResetMasterModal();
});

// ─── INICIALIZAÇÃO ────────────────────────────────────────────
// Gera senha inicial ao carregar a página
generatePassword(false); // sem efeitos na carga inicial (false = silencioso)
