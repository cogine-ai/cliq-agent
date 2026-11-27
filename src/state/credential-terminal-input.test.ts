import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { readTerminalCredentialSecret } from './credential-terminal-input.js';

// Python's standard OS PTY is the real terminal; no isTTY override, terminal
// proof, native role or execution authority is manufactured by these tests.
const harness = String.raw`
import os,sys,json,pty,selectors,subprocess,time,signal,fcntl,termios,base64
spec=json.loads(sys.stdin.read());master,slave=pty.openpty()
def child_session():
 os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
environment=dict(os.environ);environment['TERM']='xterm-256color'
p=subprocess.Popen(spec['command'],stdin=slave,stderr=slave,stdout=subprocess.PIPE,preexec_fn=child_session,env=environment)
os.close(slave);os.set_blocking(master,False);os.set_blocking(p.stdout.fileno(),False)
sel=selectors.DefaultSelector();sel.register(master,selectors.EVENT_READ);sel.register(p.stdout,selectors.EVENT_READ)
tty=bytearray();out=bytearray();ready=False;sent=False;payload=b'';offset=0;started=time.monotonic()
mode=spec['mode']
if mode in ['exact','prior_raw','cleanup_signal']:payload=b'  fixture-input-bytes  \r'
elif mode=='edited':payload=b'  fixture-input-byteX\x7fs  \r'
elif mode=='unicode':payload='  fixture-e\u0301-终端  \r'.encode('utf8')
elif mode=='maximum':payload=b'k'*65536+b'\r'
elif mode=='edited_boundary':payload=b'k'*2047+b'X\x7fk\r'
elif mode=='unicode_boundary':payload=b'k'*2047+'终端'.encode('utf8')+b'\r'
elif mode=='oversize':payload=b'k'*65537+b'\r'
elif mode=='overflow':payload=b'k'*98304+b'\r'
elif mode=='eof':payload=b'\x04'
elif mode=='interrupt':payload=b'fixture-input-bytes\x03'
try:
 while sel.get_map():
  if time.monotonic()-started>18:raise RuntimeError('owned terminal test exceeded its outer join bound')
  for key,events in sel.select(.02):
   fd=key.fd
   try:b=os.read(fd,65536)
   except BlockingIOError:continue
   except OSError as error:
    if fd==master and error.errno==5:sel.unregister(master);continue
    raise
   if not b:sel.unregister(key.fileobj);continue
   if fd==master:tty.extend(b)
   else:out.extend(b)
   if len(tty)>131072 or len(out)>4096:raise RuntimeError('owned terminal output exceeded its bound')
  if not ready and b'API key: ' in tty:
   ready=True
   if mode=='signal':p.send_signal(signal.SIGTERM);sent=True
  if ready and not sent and offset<len(payload):
   try:offset+=os.write(master,payload[offset:offset+2048])
   except BlockingIOError:pass
   except OSError:sent=True
   if offset==len(payload):sent=True
  if p.poll() is not None and not sel.get_map():break
 p.wait(timeout=1)
 print(json.dumps({'exitCode':p.returncode,'ready':ready,'sent':sent,'output':out.decode('utf8'),'ttyBase64':base64.b64encode(tty).decode('ascii')}))
finally:
 if p.poll() is None:p.kill();p.wait(timeout=2)
 os.close(master);sel.close();p.stdout.close()
`;

async function terminal(mode: string) {
  const command = [process.execPath, '--import', 'tsx', fileURLToPath(new URL('./testing/credential-terminal-child.ts', import.meta.url)), mode];
  const result = await new Promise<string>((resolve, reject) => {
    const child = execFile('/usr/bin/python3', ['-c', harness], { timeout: 22000, maxBuffer: 256 * 1024 },
      (error, stdout) => error ? reject(new Error('owned terminal fixture did not join')) : resolve(stdout));
    child.stdin!.end(JSON.stringify({ command, mode }));
  });
  const observed = JSON.parse(result), output = JSON.parse(observed.output), tty = Buffer.from(observed.ttyBase64, 'base64').toString();
  assert.equal(observed.exitCode, 0); assert.equal(observed.ready, true);
  assert.equal(/fixture-input|kkkkkkkk|\x1b/u.test(tty), false, 'only the fixed prompt and newline may leave the hidden terminal');
  assert.equal(tty, 'API key: \r\n');
  assert.equal(output.zeroed, true); assert.equal(output.rawRestored, true); assert.equal(output.pausedRestored, true);
  assert.equal(output.listenersRestored, true); assert.equal(output.signalsRestored, true);
  return output;
}

test('hidden terminal input refuses ordinary piped stdio without reading it', { skip: process.stdin.isTTY && process.stderr.isTTY }, async () => {
  await assert.rejects(readTerminalCredentialSecret(), { code: 'INVALID_REQUEST' });
});

for (const mode of ['exact', 'edited', 'unicode', 'prior_raw', 'maximum', 'edited_boundary', 'unicode_boundary']) test(`real hidden terminal preserves exact input and restores ownership (${mode})`, async () => {
  const result = await terminal(mode);
  assert.equal(result.outcome, 'read'); assert.equal(result.exact, true, `exact terminal editing returned ${result.byteCount} bytes`);
  assert.equal(result.byteCount, mode === 'maximum' ? 65536 : mode === 'edited_boundary' ? 2048 : mode === 'unicode_boundary' ? 2053
    : mode === 'unicode' ? Buffer.byteLength('  fixture-e\u0301-终端  ') : 23);
});

for (const mode of ['oversize', 'overflow', 'eof', 'interrupt', 'signal', 'cleanup_signal']) test(`real hidden terminal rejects and joins (${mode})`, async () => {
  const result = await terminal(mode);
  assert.equal(result.outcome, 'refused'); assert.equal(result.code, 'INVALID_REQUEST');
});

test('real hidden terminal retains the original ten-second input deadline', async () => {
  const result = await terminal('timeout');
  assert.equal(result.outcome, 'refused'); assert.equal(result.code, 'INVALID_REQUEST');
  assert(result.elapsedMs >= 9900 && result.elapsedMs < 13000);
});
