#!/usr/bin/env node
/**
 * Зоря.нет — сторож просвіту (личный монитор, не входит в оцениваемый клиент)
 *
 * За один запуск:
 *  1. Стучится в GET /ether (один запрос — лимит станции не трогаем)
 *  2. Проверяет печатку: подпись Ed25519 над байтами строки frame
 *  3. Смотрит фазу кадра: static / провісник / window / after
 *  4. Шлёт в Telegram: провісник, открытие просвіту, уривки листа Доглядача
 *  5. Пишет state.json ТОЛЬКО при важном изменении (ушло уведомление или
 *     пойман новый уривок), чтобы бот не засорял историю репозитория
 *
 * Переменные окружения:
 *   TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID — обязательны
 *   ZORIA_API_BASE    — по умолчанию https://zoria.net/api/v1
 *   TELEGRAM_API_BASE — по умолчанию https://api.telegram.org (меняется только в тестах)
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { subtle } from 'node:crypto';

const API_BASE = process.env.ZORIA_API_BASE || 'https://zoria.net/api/v1';
const TG_BASE = process.env.TELEGRAM_API_BASE || 'https://api.telegram.org';
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const STATE_PATH = new URL('../state.json', import.meta.url);
const TIMEOUT_MS = 10_000; // ни один запрос не висит дольше 10 с

if (!BOT_TOKEN || !CHAT_ID) {
  console.error('Не заданы TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID');
  process.exit(1);
}

// --- утилиты ---------------------------------------------------------------

const b64uToBytes = (s) =>
  new Uint8Array(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));

// Текст станции вставляется в HTML-сообщение Telegram: спецсимволы экранируем,
// иначе Telegram отвергнет сообщение целиком ("can't parse entities").
const escapeHtml = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Время → "24.09, 11:00 по Польше (2026-09-24 09:00 UTC)" */
function fmtTime(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '(время неизвестно)';
  const local = d.toLocaleString('ru-RU', {
    timeZone: 'Europe/Warsaw',
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
  return `${local} по Польше (${d.toISOString().slice(0, 16).replace('T', ' ')} UTC)`;
}

// --- состояние -------------------------------------------------------------

const EMPTY_STATE = {
  notifiedHarbinger: false,
  notifiedWindow: false,
  lastAt: null, // at последнего принятого кадра (защита от эха)
  fragments: {}, // { "3": "текст уривка" }
  fragmentsOf: null, // сколько всего уривков (поле `of`)
  fragmentsNotified: false, // собранный лист уже отправлен
};

// Изменение этих полей стоит коммита. lastAt сюда не входит: он меняется на
// каждом настоящем кадре и сохраняется только вместе с важными изменениями.
const IMPORTANT = ['notifiedHarbinger', 'notifiedWindow', 'fragments', 'fragmentsOf', 'fragmentsNotified'];
const snapshot = (s) => JSON.stringify(IMPORTANT.map((k) => s[k]));

function loadState() {
  const state = structuredClone(EMPTY_STATE);
  if (!existsSync(STATE_PATH)) return state;
  try {
    const saved = JSON.parse(readFileSync(STATE_PATH, 'utf8'));
    for (const k of Object.keys(state)) if (k in saved) state[k] = saved[k];
  } catch {
    /* битый файл — начинаем с чистого состояния */
  }
  return state;
}

const saveState = (state) => writeFileSync(STATE_PATH, JSON.stringify(state, null, 2) + '\n');

// --- Telegram --------------------------------------------------------------

/** true — сообщение ушло. Ошибки не бросает, только логирует. */
async function sendTelegram(text, html = true) {
  try {
    const res = await fetch(`${TG_BASE}/bot${BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: CHAT_ID, text, ...(html ? { parse_mode: 'HTML' } : {}) }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (res.ok) return true;
    console.error('Telegram ответил ошибкой:', res.status, await res.text().catch(() => ''));
  } catch (err) {
    console.error('Telegram недоступен:', err.message);
  }
  return false;
}

/** Длинный текст без разметки — кусками (Telegram берёт до 4096 знаков). */
async function sendLongPlain(text) {
  let ok = true;
  for (let i = 0; i < text.length; i += 4000) {
    ok = (await sendTelegram(text.slice(i, i + 4000), false)) && ok;
  }
  return ok;
}

// --- печатка станции --------------------------------------------------------

const keyCache = new Map(); // key (16 hex) -> CryptoKey

async function getVerifyKey(keyId) {
  if (keyCache.has(keyId)) return keyCache.get(keyId);

  const res = await fetch(`${API_BASE}/ether/key`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) throw new Error(`GET /ether/key -> HTTP ${res.status}`);
  const data = await res.json();
  if (data.key !== keyId) throw new Error(`ключ конверта ${keyId} не совпадает с ключом станции ${data.key}`);

  const publicKeyBytes = b64uToBytes(data.publicKey);
  const fingerprint = Buffer.from(await subtle.digest('SHA-256', publicKeyBytes)).toString('hex');
  if (fingerprint !== data.fingerprint || !fingerprint.startsWith(keyId)) {
    throw new Error('отпечаток ключа не сходится — ключ не принимаем');
  }
  // TODO (CL-04): сверить fingerprint с отпечатком из ТЗ части 1, раздел 3.

  const cryptoKey = await subtle.importKey('raw', publicKeyBytes, { name: 'Ed25519' }, false, ['verify']);
  keyCache.set(keyId, cryptoKey);
  return cryptoKey;
}

/** Проверка конверта по разделу 5.2 спецификации. Кадр-объект или null (перешкода). */
async function verifyEnvelope(envelope) {
  if (
    !envelope ||
    typeof envelope !== 'object' ||
    typeof envelope.frame !== 'string' ||
    typeof envelope.seal !== 'string' ||
    typeof envelope.key !== 'string'
  ) {
    return null; // не та форма
  }

  let key;
  try {
    key = await getVerifyKey(envelope.key);
  } catch (err) {
    console.warn('Ключ не получен/не принят:', err.message);
    return null;
  }

  let ok = false;
  try {
    ok = await subtle.verify(
      { name: 'Ed25519' },
      key,
      b64uToBytes(envelope.seal),
      new TextEncoder().encode(envelope.frame),
    );
  } catch {
    ok = false; // печатка кривой длины и т.п.
  }
  if (!ok) return null; // печатка неправильная — підробка

  let frame;
  try {
    frame = JSON.parse(envelope.frame);
  } catch {
    return null;
  }
  return frame?.v === 1 && frame.station === 'zoria' ? frame : null;
}

// --- основной сценарий -----------------------------------------------------

async function main() {
  const state = loadState();
  const before = snapshot(state);

  console.log(`Опрашиваю ${API_BASE}/ether`);
  let res;
  let body;
  try {
    res = await fetch(`${API_BASE}/ether`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    body = await res.text();
  } catch (err) {
    console.warn('Сеть недоступна или обрыв:', err.message);
    if (err.cause) console.warn('  причина (cause):', err.cause.message || err.cause);
    return; // следующий запуск по расписанию попробует снова
  }
  console.log(`HTTP ${res.status}`);

  if (res.status === 429) {
    console.warn(`Станция глушит (429), Retry-After=${res.headers.get('Retry-After')} с — пропускаем прогон`);
    return;
  }

  let envelope;
  try {
    envelope = JSON.parse(body);
  } catch {
    console.log('Тело не JSON — перешкода, пропускаем');
    return;
  }

  const frame = await verifyEnvelope(envelope);
  if (!frame) {
    console.log('Кадр не прошёл проверку (перешкода/подделка) — игнорируем');
    return;
  }

  // CL-05: старый кадр (эхо/задержка) состояние не откатывает
  if (state.lastAt && frame.at <= state.lastAt) {
    console.log(`Эхо/задержка: at=${frame.at} не новее ${state.lastAt} — игнорируем`);
    return;
  }
  state.lastAt = frame.at;
  console.log(
    `Настоящий кадр: phase=${frame.phase}, at=${frame.at}, onAir=${frame.onAir}, ` +
      `провісник=${frame.harbinger ? 'да' : 'нет'}, ` +
      `уривок=${frame.fragment ? `${frame.fragment.n}/${frame.fragment.of}` : 'нет'}`,
  );

  // Стенд крутит цикл по кругу: свежий шум без провісника = новый цикл, флаги сбрасываем.
  // На боевом сервере шум после просвіту не возвращается — там это не сработает.
  if (frame.phase === 'static' && !frame.harbinger) {
    state.notifiedHarbinger = false;
    state.notifiedWindow = false;
  }

  if (frame.harbinger && !state.notifiedHarbinger) {
    const opensMs = Date.parse(frame.at) + Number(frame.harbinger.opensIn) * 1000;
    const voice = frame.harbinger.text?.ru || frame.harbinger.text?.uk || '—';
    const sent = await sendTelegram(
      `🕯️ <b>Провісник!</b>\n` +
        `Просвіт откроется примерно ${fmtTime(opensMs)}.\n` +
        `Голос станции: ${escapeHtml(voice)}`,
    );
    if (sent) state.notifiedHarbinger = true; // не ушло — повторим в следующий запуск
  }

  if (frame.phase === 'window' && !state.notifiedWindow) {
    const sent = await sendTelegram(
      `🚨 <b>ПРОСВІТ ОТКРЫТ!</b>\n` +
        `Пора регистрироваться. Закроется ${fmtTime(frame.window?.closesAt)}.\n` +
        `API: ${API_BASE}`,
    );
    if (sent) state.notifiedWindow = true;
  }

  // CL-35: уривки листа — только из кадров с правильной печаткой, повтор номера отбрасываем
  const frag = frame.fragment;
  if (frag && typeof frag.text === 'string' && Number.isInteger(frag.n) && !(String(frag.n) in state.fragments)) {
    state.fragments[String(frag.n)] = frag.text;
    if (Number.isInteger(frag.of)) state.fragmentsOf = frag.of;
    const got = Object.keys(state.fragments).length;
    console.log(`Пойман уривок ${frag.n}/${frag.of}`);
    await sendTelegram(`📜 Уривок листа ${frag.n}/${frag.of} пойман (собрано ${got}/${state.fragmentsOf ?? '?'}).`);
  }

  const have = Object.keys(state.fragments).length;
  if (state.fragmentsOf && have >= state.fragmentsOf && !state.fragmentsNotified) {
    const letter = Array.from(
      { length: state.fragmentsOf },
      (_, i) => state.fragments[String(i + 1)] ?? '[…]',
    ).join('\n');
    if (await sendLongPlain(`📖 Лист Доглядача зібрано повністю:\n\n${letter}`)) {
      state.fragmentsNotified = true;
    }
  }

  if (snapshot(state) !== before) {
    saveState(state);
    console.log('state.json обновлён — было важное изменение');
  } else {
    console.log('Важных изменений нет — state.json не трогаем');
  }
}

main().catch((err) => {
  console.error('Необработанная ошибка:', err);
  process.exit(1);
});
