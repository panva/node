// Test run({ watch: true, cwd, isolation: 'none' }) does not reuse the
// parent process argv when spawning the watch child.
import * as common from '../common/index.mjs';
import * as fixtures from '../common/fixtures.mjs';
import assert from 'node:assert';
import { run } from 'node:test';
import { skipIfNoWatch } from '../common/watch.js';

skipIfNoWatch();

const passed = [];
const controller = new AbortController();
const stream = run({
  // Avoid delayed file creation notifications triggering a watch restart.
  cwd: fixtures.path('test-runner-watch'),
  watch: true,
  signal: controller.signal,
  isolation: 'none',
}).on('data', ({ type }) => {
  if (type !== 'test:watch:drained') return;

  stream.removeAllListeners('test:fail');
  stream.removeAllListeners('test:pass');
  controller.abort();
});

stream.on('test:watch:restarted', common.mustNotCall('test:watch:restarted'));
stream.on('test:fail', common.mustNotCall('test:fail'));
stream.on('test:pass', common.mustCall((data) => passed.push(data.name)));

for await (const { type, data } of stream) {
  if (type === 'test:diagnostic' || type === 'test:stderr') {
    console.error(data.message);
  }
}

// Validate the expected test ran by name:
assert.deepStrictEqual(passed, ['test has ran']);
