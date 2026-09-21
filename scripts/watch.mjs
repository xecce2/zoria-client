#!/usr/bin/env node
/**
 * Зоря.нет — сторож просвіту (личный монитор, не входит в оцениваемый клиент)
 *
 * Что делает:
 *  1. Раз за запуск стучится в GET /ether
 *  2. Проверяет подпись Ed25519 конверта (seal над байтами строки frame)
 *  3. Сверяет key-отпечаток с известным (production или test — берём динамически)
 *  4. Смотрит фазу кадра (static / harbinger / window / after)
 *  5. Шлёт в Telegram алерт при появлении провісника и при открытии просвіту
 *  6. Не спамит: хранит состояние в state.json (в репозитории), коммитится Action'ом
 *
 * Запуск: node scripts/watch.mjs
 * Нужны переменные окружения:
 *   TELEGRAM_BOT_TOKEN
 *   TELEGRAM_CHAT_ID
 *   ZORIA_API_BASE       (по умолчанию https://zoria.net/api/v1, для теста — https://stand.zoria.net/api/v1)
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { subtle } from 'node:crypto';

const API_BASE = process.env.ZORIA_API_BASE || 'https://zoria.net/api/v1';
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const STATE_PATH = new URL('../state.json', import.meta.url);

if (!BOT_TOKEN || !CHAT_ID) {
  console.error('Не заданы TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID');
  process.exit(1);
}

// --- утилиты base64url -------------------------------------------------

function b64uToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = Buffer.from(b64, 'base64');
  return new Uint8Array(bin);
}

// --- состояние -----------------------------------------------------------

function loadState() {
  const empty = {
    lastKnownKey: null,
    notifiedHarbinger: false,
    notifiedWindow: false,
    lastAt: null,
    fragments: {}, // { "3": "текст уривка" }
    fragmentsOf: null, // общее число уривков (из поля `of`)
    fragmentsNotified: false, // письмо уже собрано и отправлено целиком
  };
  if (!existsSync(STATE_PATH)) return empty;
  try {
    return { ...empty, ...JSON.parse(readFileSync(STATE_PATH, 'utf8')) };
  } catch {
    return empty;
  }
}

function saveState(state) {
  writeFileSync(STATE_PATH, JSON.stringify(state, null, 2) + '\n');
}

// --- Telegram --------------------------------------------------------------

async function sendTelegram(text) {
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: CHAT_ID, text, parse_mode: 'HTML' }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    console.error('Telegram sendMessage failed:', res.status, body);
  }
}

// --- проверка ключа ----------------------------------------------------

const keyCache = new Map(); // key(hex16) -> CryptoKey

async function getVerifyKey(keyId) {
  if (keyCache.has(keyId)) return keyCache.get(keyId);

  const res = await fetch(`${API_BASE}/ether/key`);
  if (!res.ok) throw new Error(`GET /ether/key failed: ${res.status}`);
  const data = await res.json();

  if (data.key !== keyId) {
    // Сервер вернул другой ключ, чем тот, что просил конверт — незнакомый ключ.
    throw new Error(`Ключ ${keyId} не совпадает с текущим ключом станции ${data.key}`);
  }

  const publicKeyBytes = b64uToBytes(data.publicKey);

  // Сверка отпечатка: SHA-256(publicKey) должен совпасть с data.fingerprint
  const digest = await subtle.digest('SHA-256', publicKeyBytes);
  const computedFingerprint = Buffer.from(digest).toString('hex');
  if (computedFingerprint !== data.fingerprint) {
    throw new Error('Отпечаток ключа не сходится с посчитанным — подозрительно, прерываю');
  }

  // TODO (опционально): здесь можно захардкодить эталонный fingerprint из ТЗ
  // части 1 (раздел 3) и сверить его тоже — доп. защита от подмены /ether/key.
  // const KNOWN_FINGERPRINT = '...';
  // if (data.fingerprint !== KNOWN_FINGERPRINT) throw new Error('fingerprint не совпадает с ТЗ');

  const cryptoKey = await subtle.importKey(
    'raw',
    publicKeyBytes,
    { name: 'Ed25519' },
    false,
    ['verify'],
  );

  keyCache.set(keyId, cryptoKey);
  return cryptoKey;
}

/**
 * Проверяет конверт по правилам раздела 5.2 спецификации клиента.
 * Возвращает разобранный frame (объект) при успехе, либо null (перешкода).
 */
async function verifyEnvelope(envelope) {
  if (
    !envelope ||
    typeof envelope !== 'object' ||
    typeof envelope.frame !== 'string' ||
    typeof envelope.seal !== 'string' ||
    typeof envelope.key !== 'string'
  ) {
    return null; // не той форми — перешкода
  }

  let verifyKey;
  try {
    verifyKey = await getVerifyKey(envelope.key);
  } catch (err) {
    console.warn('Не удалось получить/проверить ключ:', err.message);
    return null;
  }

  const sealBytes = b64uToBytes(envelope.seal);
  const frameBytes = new TextEncoder().encode(envelope.frame);

  const ok = await subtle.verify({ name: 'Ed25519' }, verifyKey, sealBytes, frameBytes);
  if (!ok) {
    return null; // печатка неправильна — підробка
  }

  let frame;
  try {
    frame = JSON.parse(envelope.frame);
  } catch {
    return null;
  }

  if (frame.v !== 1 || frame.station !== 'zoria') {
    return null;
  }

  return frame;
}

// --- основной сценарий ---------------------------------------------------

async function main() {
  const state = loadState();

  console.log(`Опрашиваю ${API_BASE}/ether`);

  let res;
  try {
    res = await fetch(`${API_BASE}/ether`, { signal: AbortSignal.timeout(10_000) });
  } catch (err) {
    console.warn('Сеть недоступна или обрыв:', err.message);
    if (err.cause) console.warn('  причина (cause):', err.cause.message || err.cause);
    return; // просто выходим, следующий запуск по расписанию попробует снова
  }

  if (res.status === 429) {
    const retryAfter = res.headers.get('Retry-After');
    console.warn(`429 jammed, Retry-After=${retryAfter}s — пропускаем этот прогон`);
    return;
  }

  let envelope;
  try {
    envelope = await res.json();
  } catch {
    console.log('Тело не JSON — перешкода, пропускаем');
    return;
  }

  const frame = await verifyEnvelope(envelope);
  if (!frame) {
    console.log('Кадр не прошёл проверку (перешкода/подделка/битый) — игнорируем');
    return;
  }

  // Старый кадр не откатывает состояние (правило CL-05)
  if (state.lastAt && frame.at <= state.lastAt) {
    console.log(`Эхо/задержка: at=${frame.at} не новее последнего ${state.lastAt}`);
    return;
  }
  state.lastAt = frame.at;

  console.log(`Настоящий кадр: phase=${frame.phase}, at=${frame.at}, onAir=${frame.onAir}`);

  // --- провісник ---
  if (frame.harbinger && !state.notifiedHarbinger) {
    const opensAtMs = new Date(frame.at).getTime() + frame.harbinger.opensIn * 1000;
    const opensAtIso = new Date(opensAtMs).toISOString();
    const text =
      `🕯️ <b>Провісник!</b>\n` +
      `Просвіт должен открыться примерно в ${opensAtIso} (UTC).\n` +
      `Голос станции: ${frame.harbinger.text?.ru || frame.harbinger.text?.uk || '—'}`;
    await sendTelegram(text);
    state.notifiedHarbinger = true;
  }

  // --- открытие просвіту ---
  if (frame.phase === 'window' && !state.notifiedWindow) {
    const closesAt = frame.window?.closesAt || '?';
    const text =
      `🚨 <b>ПРОСВІТ ОТКРЫТ!</b>\n` +
      `Пора регистрироваться. Закрытие (пока): ${closesAt}\n` +
      `API: ${API_BASE}`;
    await sendTelegram(text);
    state.notifiedWindow = true;
  }

  // --- уривки листа Доглядача (CL-35) ---
  if (frame.fragment && frame.fragment.text) {
    const { n, of, text: fragText } = frame.fragment;
    const key = String(n);
    if (!(key in state.fragments)) {
      state.fragments[key] = fragText;
      state.fragmentsOf = of;
      console.log(`Пойман уривок ${n}/${of}`);
      await sendTelegram(`📜 Уривок листа ${n}/${of} пойман (${Object.keys(state.fragments).length}/${of} всего).`);
    }
  }

  const haveAllFragments =
    state.fragmentsOf && Object.keys(state.fragments).length >= state.fragmentsOf;

  if (haveAllFragments && !state.fragmentsNotified) {
    const fullText = Array.from({ length: state.fragmentsOf }, (_, i) => state.fragments[String(i + 1)] || '???')
      .join(' ');
    await sendTelegram(`📖 <b>Лист Доглядача зібрано повністю:</b>\n\n${fullText}`);
    state.fragmentsNotified = true;
  }

  // Если фаза откатилась в static (например, тест на стенде пошёл по кругу) —
  // сбрасываем флаги, чтобы не потерять следующий реальный цикл.
  if (frame.phase === 'static' && !frame.harbinger) {
    state.notifiedHarbinger = false;
    state.notifiedWindow = false;
  }

  saveState(state);
}

main().catch((err) => {
  console.error('Необработанная ошибка:', err);
  process.exit(1);
});
