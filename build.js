#!/usr/bin/env node
'use strict';
/*
 * Inline core + app + sample data into single-file pages:
 *   dist/index.html       artifact body (the host adds <!doctype>/<head>)
 *   dist/standalone.html  full document for opening offline from disk
 *   demo.html             same document at the repo root, served by GitHub Pages
 */
const fs = require('node:fs');
const path = require('node:path');
const r = (p) => fs.readFileSync(path.join(__dirname, p), 'utf8');

// newest non-empty eval result (an interrupted run leaves an empty file)
const evalFile = fs.readdirSync(path.join(__dirname, 'results'))
  .filter((f) => /^inject-eval-.*\.md$/.test(f) && fs.statSync(path.join(__dirname, 'results', f)).size > 0)
  .sort((a, b) => fs.statSync(path.join(__dirname, 'results', b)).mtimeMs - fs.statSync(path.join(__dirname, 'results', a)).mtimeMs)[0];
const data = {
  config: r('samples/fgt-demo.conf'),
  logs: r('samples/fgt-logs.log'),
  evalMd: evalFile ? r(`results/${evalFile}`) : '',
  evalNote: evalFile ? (fs.existsSync(path.join(__dirname, 'results/eval-note.txt')) ? r('results/eval-note.txt').trim() : '') : '',
};
// keep "</script>" sequences in data from closing the tag
const safe = (s) => s.replace(/<\/script/gi, '<\\/script').replace(/<!--/g, '<\\!--');
const body = r('web/page.html')
  .replace('/*__CORE__*/', () => safe(r('src/core.js')))
  .replace('/*__DATA__*/', () => `window.NETSEC_DATA = ${safe(JSON.stringify(data))};`)
  .replace('/*__APP__*/', () => safe(r('src/app.js')));

// standalone page: no connect/form/frame targets, so the page cannot send data anywhere; only the Google Fonts stylesheet loads
const CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src data:; connect-src 'none'; form-action 'none'; frame-src 'none'; base-uri 'none'";
fs.mkdirSync(path.join(__dirname, 'dist'), { recursive: true });
fs.writeFileSync(path.join(__dirname, 'dist/index.html'), body);
const standalone = `<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n<meta http-equiv="Content-Security-Policy" content="${CSP}">\n<style>:root{color-scheme:light}body{margin:0}[hidden]{display:none!important}img{max-width:100%}</style>\n</head>\n<body>\n${body}\n</body>\n</html>\n`;
fs.writeFileSync(path.join(__dirname, 'dist/standalone.html'), standalone);
// GitHub Pages serves the repo root: the demo is demo.html there (index.html is the NetSec Board
// landing page, built by scripts/build-pages.js)
fs.writeFileSync(path.join(__dirname, 'demo.html'), standalone);
console.log(`dist/index.html ${(body.length / 1024).toFixed(0)} KB, dist/standalone.html, eval: ${evalFile || 'none'}`);
