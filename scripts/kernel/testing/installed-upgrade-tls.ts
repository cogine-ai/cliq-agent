// Owned qualification TLS only. Linux OpenSSL3 generates the ephemeral key
// into its anonymous stdout pipe; Darwin retains its supported stdin recipe.
// The caller wipes privatePem after createServer consumes it. The complete
// child output is scanned as two original streams, then wiped on every path.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createPublicKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { emitQualificationFailure } from './qualification-failure-diagnostic.js';
function block(bytes: Buffer, label: string) {
  const begin=Buffer.from(`-----BEGIN ${label}-----`), end=Buffer.from(`-----END ${label}-----`);
  const start=bytes.indexOf(begin);
  assert(start>=0,'owned TLS output must contain its one expected PEM block');
  assert.equal(bytes.indexOf(begin,start+begin.length),-1,'owned TLS output must not duplicate a PEM block');
  const last=bytes.indexOf(end,start+begin.length);
  assert(last>=0,'owned TLS output must close its expected PEM block');
  return {start,end:last+end.length};
}

export function createUpgradeTlsMaterial(scan: (bytes: Uint8Array) => void) {
  let privatePem: Buffer | undefined;
  const originalOutputs: Buffer[] = [], started=process.hrtime.bigint();
  const run = (args: string[], input?: Buffer) => {
    const remaining=5000-Math.ceil(Number(process.hrtime.bigint()-started)/1_000_000);
    assert(remaining>0,'owned TLS preparation retains its original five-second total deadline');
    const made=spawnSync('/usr/bin/openssl',args,{...(input ? {input} : {}),
      env:{PATH:'/usr/sbin:/usr/bin:/sbin:/bin',LANG:'C',LC_ALL:'C'},
      timeout:remaining,killSignal:'SIGKILL',maxBuffer:65536});
    assert(Buffer.isBuffer(made.stdout) && Buffer.isBuffer(made.stderr));
    originalOutputs.push(made.stdout,made.stderr);
    scan(made.stdout);scan(made.stderr);
    assert.equal(made.error,undefined,'owned TLS certificate process must join');
    assert.equal(made.signal,null);assert.equal(made.status,0);
    return made.stdout;
  };
  try {
    const suffix=['-sha256','-days','1','-subj','/CN=installed-upgrade-fixture.invalid',
      '-addext','subjectAltName=DNS:installed-upgrade-fixture.invalid'];
    let output: Buffer, key: ReturnType<typeof block> | undefined;
    if (process.platform === 'linux') {
      // Linux Node stdio cannot be reopened by /dev/stdin. OpenSSL 3's fixed
      // stdout convention avoids a file; LibreSSL treats '-' as a filename,
      // so reject it before generating any private material or using keyout.
      const version=run(['version']);
      assert(version.every(byte=>byte<=127) && /^OpenSSL 3\.[0-9]+\.[0-9]+[\x20-\x7e]*\r?\n?$/u.test(version.toString('ascii')),
        'owned Linux TLS qualification requires its fixed OpenSSL 3 profile');
      output=run(['req','-x509','-newkey','rsa:2048','-nodes','-keyout','-','-out','-',...suffix]);
      const labels=['PRIVATE KEY','RSA PRIVATE KEY'].filter(label=>output.includes(Buffer.from(`-----BEGIN ${label}-----`)));
      assert.equal(labels.length,1,'owned TLS output must contain exactly one private key');
      key=block(output,labels[0]!);privatePem=Buffer.from(output.subarray(key.start,key.end));
    } else {
      // Darwin's descriptor filesystem supports the existing stdin recipe.
      // No ambiguous private-key output filename is ever passed to LibreSSL.
      const pair=generateKeyPairSync('rsa',{modulusLength:2048});
      privatePem=Buffer.from(pair.privateKey.export({type:'pkcs8',format:'pem'}));
      output=run(['req','-x509','-new','-key','/dev/stdin',...suffix],privatePem);
    }
    const cert=block(output,'CERTIFICATE');
    if (key) assert(key.end<=cert.start || cert.end<=key.start,'owned TLS PEM blocks cannot overlap');
    for (let index=0;index<output.length;index++) {
      if (key && index>=key.start && index<key.end || index>=cert.start && index<cert.end) continue;
      assert([9,10,13,32].includes(output[index]!),'owned TLS output must contain only its exact key/certificate blocks');
    }
    assert(privatePem.length>=256 && privatePem.length<=8192);
    const certificatePem=Buffer.from(output.subarray(cert.start,cert.end)), certificate=new X509Certificate(certificatePem);
    assert(certificate.publicKey.export({type:'spki',format:'der'}).equals(createPublicKey(privatePem).export({type:'spki',format:'der'})),
      'owned TLS certificate must bind its exact generated private key');
    assert.equal(certificate.verify(certificate.publicKey),true,'owned TLS certificate must be self-signed');
    assert(process.hrtime.bigint()-started<=5_000_000_000n,'owned TLS preparation must finish within its original five-second total deadline');
    return { privatePem, certificatePem };
  } catch (error) { privatePem?.fill(0); emitQualificationFailure('tls',error); throw error; }
  finally {
    for (const bytes of originalOutputs) bytes.fill(0);
  }
}
