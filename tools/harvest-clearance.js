#!/usr/bin/env node
// Снять `cf_clearance` настоящим Chrome — чтобы движок потом ходил по нему.
//
//   node tools/harvest-clearance.js <url> [секунд] [файл]
//   PROFILE=/tmp/мой-профиль node tools/harvest-clearance.js https://цель/
//
// Замок Cloudflare привязан к отпечатку TLS того, кто его получил, к выходному
// адресу и к версии браузера. Движок выдаёт себя за Chrome 151 и его JA4
// совпадает с настоящим знак в знак, поэтому снятый здесь замок движок
// принимает. Проверено на заставе `scrapingcourse.com/cloudflare-challenge`:
// без замка «Just a moment…», с замком — сама страница.
//
// Браузер видимый (DISPLAY=:0): безголовый управляемую заставу проходит
// заметно хуже. Ничего в страницу не внедряется — только сеть и список кук,
// как в `netwatch.js`: инструмент, меняющий измеряемое, здесь не нужен.
//
// Дальше замок переносится в движок:
//
//   nokk --load https://цель/ --session-store ./sess --session cf \
//        --import-cookies cf_clearance.json
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');

const PORT = +(process.env.PORT || 9340);
const URL_ = process.argv[2];
const СРОК = +(process.argv[3] || 40) * 1000;
const ФАЙЛ = process.argv[4] || 'cf_clearance.json';
if (!URL_) {
  console.error('нужен адрес: node tools/harvest-clearance.js <url> [секунд] [файл]');
  process.exit(2);
}

const chrome = spawn('google-chrome', [
  `--remote-debugging-port=${PORT}`,
  `--user-data-dir=${process.env.PROFILE || '/tmp/nokk-harvest'}`,
  '--no-first-run', '--no-default-browser-check', '--window-size=1280,900',
  ...(process.env.PROXY ? [`--proxy-server=${process.env.PROXY}`] : []),
  'about:blank',
], { env: { ...process.env, DISPLAY: process.env.DISPLAY || ':0' }, stdio: 'ignore' });

const get = (path) => new Promise((res, rej) => {
  const попытка = (n) => http.get({ host: '127.0.0.1', port: PORT, path }, (r) => {
    let b = ''; r.on('data', (d) => b += d); r.on('end', () => res(JSON.parse(b)));
  }).on('error', (e) => (n > 0 ? setTimeout(() => попытка(n - 1), 400) : rej(e)));
  попытка(50);
});

const конец = (код) => {
  try { chrome.kill(); } catch (e) {}
  // Выход сразу после печати обрезает вывод, когда он идёт в файл.
  setTimeout(() => process.exit(код), 60);
};

(async () => {
  const список = await get('/json/list');
  const вкладка = список.find((t) => t.type === 'page');
  const ws = new WebSocket(вкладка.webSocketDebuggerUrl);
  let id = 0;
  const ждут = new Map();
  const send = (method, params = {}) => new Promise((res) => {
    const i = ++id; ждут.set(i, res);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && ждут.has(m.id)) { ждут.get(m.id)(m.result); ждут.delete(m.id); }
  });
  await new Promise((r) => ws.addEventListener('open', r));
  await send('Network.enable');
  await send('Page.enable');
  await send('Page.navigate', { url: URL_ });

  // Ждём не по часам, а по делу: как только замок появился — уходим. Застава
  // с проверкой в фоне отдаёт его через несколько секунд, управляемая — после
  // нажатия, и лишнее ожидание тут стоит дороже, чем кажется: каждое
  // обращение к заставе тратит доверие к адресу.
  const хост = new URL(URL_).hostname;
  const корень = хост.split('.').slice(-2).join('.');
  const срок = Date.now() + СРОК;
  let замок = null, куки = [];
  while (Date.now() < срок) {
    await new Promise((r) => setTimeout(r, 1000));
    const { cookies } = await send('Network.getAllCookies');
    куки = cookies.filter((c) => c.domain.replace(/^\./, '').endsWith(корень));
    замок = куки.find((c) => c.name === 'cf_clearance') || null;
    if (замок) break;
  }

  const банка = {};
  for (const c of куки) банка[c.name] = c.value;
  fs.writeFileSync(ФАЙЛ, JSON.stringify({ cookies: банка, domain: хост, url: URL_ }, null, 1));
  const имена = куки.map((c) => c.name).join(', ');
  process.stdout.write(
    `кук с ${корень}: ${куки.length} (${имена})\n`
    + (замок ? `cf_clearance: ${замок.value.slice(0, 32)}… → ${ФАЙЛ}\n`
             : `cf_clearance не появился за ${СРОК / 1000} с — в файле только остальные куки\n`),
    () => конец(замок ? 0 : 1),
  );
})().catch((e) => {
  process.stdout.write(`ошибка: ${e.message}\n`, () => конец(2));
});
