'use strict';
/*
 * One pull per source at a time, across processes: the server's scheduler, "Pull now" and
 * `cli/board.js pull` from system cron all take <dataDir>/pull-<source>.lock. Two runs would
 * read the same cursor and count every event twice.
 *
 * The file holds the owner's pid. It is stale (taken over) when that process is gone, when the
 * pid is our own (in a container every run can get the same pid, e.g. 1), or when it is older
 * than STALE_MS (a pid reused by an unrelated process).
 */
const fs = require('node:fs');
const path = require('node:path');

const STALE_MS = 15 * 60000;

function stale(file) {
  let pid = 0, mtime = 0;
  try { pid = Number(fs.readFileSync(file, 'utf8')) || 0; mtime = fs.statSync(file).mtimeMs; } catch { return true; }
  if (!pid || pid === process.pid || Date.now() - mtime > STALE_MS) return true;
  try { process.kill(pid, 0); return false; } catch (e) { return e.code !== 'EPERM'; }
}

/** Returns { release() } or null when another live run holds the lock. */
function takeLock(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = fs.openSync(file, 'wx', 0o600);
      fs.writeSync(fd, String(process.pid)); fs.closeSync(fd);
      let released = false;
      return {
        release: () => {
          if (released) return;
          released = true;
          try { if (fs.readFileSync(file, 'utf8') === String(process.pid)) fs.unlinkSync(file); } catch { /* gone */ }
        },
      };
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      if (!stale(file)) return null;
      try { fs.unlinkSync(file); } catch { /* raced with another taker */ }
    }
  }
  return null;
}

const pullLock = (dataDir, source) => takeLock(path.join(dataDir, `pull-${source}.lock`));

module.exports = { takeLock, pullLock, STALE_MS };
