#!/usr/bin/env node
/**
 * Автономный тест проверки подписи на эталонных кадрах A/B/C/D
 * из "Специфікація клієнта", розділ 5.2. Сети не требует.
 *
 * Запуск: node scripts/verify.test.mjs
 */

import { subtle } from 'node:crypto';

function b64uToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

// Навчальний ключ зі специфікації клієнта (розділ 5.2)
const TEST_PUBLIC_KEY_B64U = 'GQgsc8G1w5aXEnExpTBE597_7acc0vGKMAT5wUW4L5g';
const TEST_FINGERPRINT = 'f3a436df65614f08635f18fe0f64f145285203f1faa2905ecb25ffb90969a7de';
const TEST_KEY_ID = 'f3a436df65614f08';

const frames = {
  A: {
    label: 'Кадр A: справжній (шум, провісник, уривок) — очікується SIGNAL',
    envelope: {
      frame:
        '{"v":1,"kind":"signal","station":"zoria","at":"2026-09-24T03:00:00.000Z","phase":"static","window":null,"harbinger":{"opensIn":21600,"text":{"uk":"...тріск... у шумі несуча... слабка, рівна... хтось тримає канал...","ru":"...треск... в шуме несущая... слабая, ровная... кто-то держит канал..."}},"fragment":{"n":3,"of":12,"text":"навчальний уривок"},"onAir":0}',
      seal: 'NEcYfpe3oNX3SMBFWWFgWbkhLGKIoLELoaQn62BtuElLU213zmgzXBUPtQbJMhGf4jxbPjIf9oKXIFOpuYrgCw',
      key: 'f3a436df65614f08',
    },
    expect: 'signal',
  },
  B: {
    label: 'Кадр B: підробка (хибний просвіт) — очікується REJECT (bad seal)',
    envelope: {
      frame:
        '{"v":1,"kind":"signal","station":"zoria","at":"2026-09-24T03:00:05.000Z","phase":"window","window":{"opensAt":"2026-09-24T02:40:00.000Z","closesAt":"2026-09-24T13:10:00.000Z"},"harbinger":null,"fragment":null,"onAir":17}',
      seal: 'tyynPbJxE4itFop4uKs0W9TL1CRfwHNZ3HHBFFknbihg4I403hmaEL9MDcboucrllUmeKvJQfr70eHKBPLJfAg',
      key: 'f3a436df65614f08',
    },
    expect: 'reject',
  },
  C: {
    label: 'Кадр C: битий (обрезан) — очікується REJECT (parse error)',
    raw: '{"frame":"{\\"v\\":1,\\"kind\\":\\"signal\\",\\"station\\":\\"zoria\\",\\"at\\":\\"2026-09-24T03:00:00.000Z\\",\\"phase\\":\\"static\\",\\"',
    expect: 'reject',
  },
  D: {
    label: 'Кадр D: справжній журнал у просвіт — очікується SIGNAL',
    envelope: {
      frame:
        '{"v":1,"kind":"roll","station":"zoria","at":"2026-09-24T09:05:00.000Z","phase":"window","window":{"opensAt":"2026-09-24T09:00:00.000Z","closesAt":"2026-09-24T19:00:00.000Z"},"harbinger":null,"fragment":null,"onAir":2,"roll":[{"n":1,"at":"2026-09-24T09:00:04.311Z","sinceOpen":4,"name":"Північна вахта"},{"n":2,"at":"2026-09-24T09:01:30.020Z","sinceOpen":90,"name":"Stitch"}]}',
      seal: '_y5ZQ4FXV2BUeuWxFXFAzVcg1ygpokZElCv-eQvT88JzAiPlUvJUg6wlKYTd-6Ihv9VFkbYlZCJmbb_aAQ9OAA',
      key: 'f3a436df65614f08',
    },
    expect: 'signal',
  },
};

async function main() {
  // 1. Проверяем сам ключ — отпечаток должен совпасть
  const publicKeyBytes = b64uToBytes(TEST_PUBLIC_KEY_B64U);
  const digest = await subtle.digest('SHA-256', publicKeyBytes);
  const computedFingerprint = Buffer.from(digest).toString('hex');
  const fpOk = computedFingerprint === TEST_FINGERPRINT;
  console.log(`[key] fingerprint совпадает: ${fpOk ? 'OK' : 'FAIL'}`);
  if (!fpOk) {
    console.error(`  ожидалось: ${TEST_FINGERPRINT}`);
    console.error(`  получено:  ${computedFingerprint}`);
    process.exitCode = 1;
  }

  const verifyKey = await subtle.importKey(
    'raw',
    publicKeyBytes,
    { name: 'Ed25519' },
    false,
    ['verify'],
  );

  let allOk = fpOk;

  for (const [id, def] of Object.entries(frames)) {
    let outcome;
    try {
      // Кадр C приходит как текст, не парсящийся в JSON вовсе
      const body = def.raw ?? JSON.stringify(def.envelope);
      let envelope;
      try {
        envelope = JSON.parse(body);
      } catch {
        outcome = 'reject';
      }

      if (outcome !== 'reject') {
        if (
          !envelope ||
          typeof envelope.frame !== 'string' ||
          typeof envelope.seal !== 'string' ||
          typeof envelope.key !== 'string' ||
          envelope.key !== TEST_KEY_ID
        ) {
          outcome = 'reject';
        } else {
          const sealBytes = b64uToBytes(envelope.seal);
          const frameBytes = new TextEncoder().encode(envelope.frame);
          const sealOk = await subtle.verify({ name: 'Ed25519' }, verifyKey, sealBytes, frameBytes);
          outcome = sealOk ? 'signal' : 'reject';
        }
      }
    } catch (err) {
      console.error(`  [${id}] исключение: ${err.message}`);
      outcome = 'reject';
    }

    const pass = outcome === def.expect;
    allOk = allOk && pass;
    console.log(`[${id}] ${def.label} -> ${outcome} ${pass ? 'OK' : 'FAIL (expected ' + def.expect + ')'}`);
  }

  if (!allOk) {
    console.error('\nЕсть провалившиеся тесты.');
    process.exitCode = 1;
  } else {
    console.log('\nВсе тесты прошли.');
  }
}

main();
