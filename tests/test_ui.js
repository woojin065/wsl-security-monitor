// Exercise clipboard behavior without dependencies or a browser installation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const nodes = new Map();
function node(id) {
  if (!nodes.has(id)) nodes.set(id, {
    textContent: '', className: '', value: '', shown: false, focused: false, selected: false,
    showModal() {this.shown = true;}, close() {this.shown = false;},
    focus() {this.focused = true;}, select() {this.selected = true;}
  });
  return nodes.get(id);
}
let copied = '';
const context = vm.createContext({
  document: {getElementById: node},
  navigator: {clipboard: {writeText: async text => {copied = text;}}},
  fetch: () => new Promise(() => {}), // No network requests during this test.
  setInterval: () => {}, Date, Set, JSON
});
vm.runInContext(fs.readFileSync('static/app.js', 'utf8'), context);
vm.runInContext(`current = {findings: [
  {id: 'a', severity: 'high', title: '권한 문제', target: '/project/a', evidence: '권한 777', fix: '권한 검토', verify: 'stat 검사'},
  {id: 'b', severity: 'medium', title: '포트 문제', target: '0.0.0.0:8000', evidence: '전체 주소 수신', fix: '바인딩 변경', verify: 'ss 검사'}
]}; selected.add('a'); selected.add('b');`, context);
(async () => {
  node('copy-selected').onclick();
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(copied.includes('권한 문제'));
  assert.ok(copied.includes('포트 문제'));
  assert.ok(copied.includes('AGENTS.md'));
  assert.ok(copied.includes('외부에 전송하지'));
  assert.ok(copied.includes('현재도 유효한지 재확인'));
  context.navigator.clipboard.writeText = async () => {throw new Error('clipboard unavailable');};
  await vm.runInContext("copy('수동 복사 내용')", context);
  assert.equal(node('copy-text').value, '수동 복사 내용');
  assert.equal(node('copy-dialog').shown, true);
  assert.equal(node('copy-text').selected, true);
  vm.runInContext('selected.clear()', context);
  node('copy-selected').onclick();
  assert.equal(node('message').textContent, '복사할 문제를 선택하세요.');
  console.log('UI clipboard: multi-select, safety context, fallback and empty selection passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
