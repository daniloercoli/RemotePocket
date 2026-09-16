const test = require('node:test');
const assert = require('node:assert/strict');
const {webcrypto, pbkdf2Sync, createHmac, createHash} = require('node:crypto');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

function app() {
  const elements = new Map(), timers = new Map();
  let nextTimer = 0;
  const element = () => ({value:'',textContent:'',children:[],dataset:{},
    appendChild(child){this.children.push(child);},removeAttribute(name){delete this[name];},setAttribute(){},focus(){}});
  const $ = id => {if (!elements.has(id)) elements.set(id,element()); return elements.get(id);};
  class Socket {
    static OPEN = 1;
    readyState = 1;
    sent = [];
    close(){this.closed=true;this.readyState=3;}
    send(message){this.sent.push(JSON.parse(message));}
    deliver(message){return this.onmessage({data:JSON.stringify(message)});}
  }
  const scope = vm.createContext({crypto:webcrypto, TextEncoder, TextDecoder, Uint8Array,
    ArrayBuffer, DataView, btoa, atob, Blob, WebSocket:Socket,
    console:{info(){},error(){}},location:{protocol:'https:',host:'desk.example.com'},
    document:{getElementById:$,createElement:element,querySelectorAll:()=>[]},
    localStorage:{getItem(){},setItem(){},removeItem(){}},
    setInterval(){},setTimeout(fn){const id=++nextTimer;timers.set(id,fn);return id;},clearTimeout(id){timers.delete(id);},
    URL:{revokeObjectURL(){}},
  });
  for (const file of ['device-auth.js','console.js']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname,'../app/static',file),'utf8'),scope);
  }
  const run = code => vm.runInContext(code,scope);
  run("state.token='owner'; connectConsoleWs()");
  const ws = run('state.ws');
  async function start(password='caffè☕🔒device') {
    $('devicePassword').value=password;
    await run("startDeviceSession('dev_test', $('devicePassword'))");
    const request=ws.sent.find(value=>value.type==='session_challenge_request');
    return {type:'session_challenge',deviceId:'dev_test',clientNonce:request.clientNonce,
      nonce:request.clientNonce+'a'.repeat(64),challengeId:'x'.repeat(43),
      salt:Buffer.alloc(16,7).toString('base64'),iterations:600000,expiresIn:60};
  }
  return {scope,run,ws,$,timers,start};
}

test('WebCrypto proof matches RFC 7677 published vector',async()=>{
  const a=app();
  const proof=await a.run(`(async()=>{
    const key=await DeviceAuth.importPassword(new TextEncoder().encode('pencil'));
    return DeviceAuth.proof(key,{deviceId:'user',clientNonce:'rOprNGfwEbeRWgbNEkqO',
      nonce:'rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0',
      salt:'W22ZaJ0SNY7soEsUEjb6gQ==',iterations:4096});
  })()`);
  assert.equal(proof.proof,'dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=');
  assert.equal(proof.serverProof,'6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=');
});

test('session opening sends only a proof, clears password and authenticates server',async()=>{
  const a=app(), password='caffè☕🔒device';
  const challenge=await a.start(password);
  assert.equal(a.$('devicePassword').value,'');
  assert.equal(a.run("state.pendingDeviceAuth.get('dev_test').key.extractable"),false);
  await a.ws.deliver(challenge);
  const sent=a.ws.sent[1];
  assert.equal(sent.type,'session_start_request');
  assert.equal('devicePassword' in sent,false);
  assert.equal(JSON.stringify(a.ws.sent).includes(password),false);
  assert.equal(a.run("state.pendingDeviceAuth.get('dev_test').key"),null);
  const salted=pbkdf2Sync(password,Buffer.from(challenge.salt,'base64'),600000,32,'sha256');
  const hmac=(key,value)=>createHmac('sha256',key).update(value).digest();
  const clientKey=hmac(salted,'Client Key'), storedKey=createHash('sha256').update(clientKey).digest();
  const transcript=`n=dev_test,r=${challenge.clientNonce},r=${challenge.nonce},s=${challenge.salt},i=600000,c=biws,r=${challenge.nonce}`;
  const signature=hmac(storedKey,transcript);
  assert.equal(sent.proof,Buffer.from(clientKey.map((byte,index)=>byte^signature[index])).toString('base64'));
  const serverProof=hmac(hmac(salted,'Server Key'),transcript).toString('base64');
  a.ws.deliver({type:'session_started',deviceId:'dev_test',sessionId:'session',serverProof});
  assert.equal(a.run('state.sessions.size'),1);
  assert.equal(a.run('state.pendingDeviceAuth.size'),0);
  assert.equal(a.timers.size,0);
});

test('wrong server proof closes the connection without accepting session',async()=>{
  const a=app();
  await a.ws.deliver(await a.start());
  a.ws.deliver({type:'session_started',deviceId:'dev_test',sessionId:'session',serverProof:'incorrect'});
  assert.equal(a.ws.closed,true);
  assert.equal(a.run('state.sessions.size'),0);
  assert.equal(a.run('state.pendingDeviceAuth.size'),0);
});

test('duplicate challenge produces only one proof',async()=>{
  const a=app(), challenge=await a.start();
  await Promise.all([a.ws.deliver(challenge),a.ws.deliver(challenge)]);
  await a.ws.deliver(challenge);
  assert.equal(a.ws.sent.filter(value=>value.type==='session_start_request').length,1);
});

for (const change of [{clientNonce:'b'.repeat(64)},{nonce:'b'.repeat(128)},{iterations:1},{iterations:1000000000},{salt:'bad'},{challengeId:'bad'}]) {
  test(`invalid challenge is rejected: ${Object.keys(change)[0]}=${Object.values(change)[0]}`,async()=>{
    const a=app(), challenge=await a.start();
    await a.ws.deliver({...challenge,...change});
    assert.equal(a.ws.sent.length,1);
    assert.equal(a.run('state.pendingDeviceAuth.size'),0);
  });
}

for (const action of ['clearCredentials()','connectConsoleWs()']) {
  test(`pending computation cannot send after ${action}`,async()=>{
    const a=app(), challenge=await a.start();
    let resume;
    a.scope.pause=new Promise(resolve=>{resume=resolve;});
    a.run('const computeProof=DeviceAuth.proof; DeviceAuth.proof=async(...args)=>{await pause;return computeProof(...args);};');
    const response=a.ws.deliver(challenge);
    a.run(action);
    resume();
    await response;
    assert.equal(a.ws.sent.length,1);
    assert.equal(a.run('state.pendingDeviceAuth.size'),0);
  });
}

test('timeout drops the pending key and ignores a late challenge',async()=>{
  const a=app(), challenge=await a.start();
  for (const callback of [...a.timers.values()]) callback();
  await a.ws.deliver(challenge);
  assert.equal(a.run('state.pendingDeviceAuth.size'),0);
  assert.equal(a.ws.sent.length,1);
});

test('missing WebCrypto requires secure context and never sends a password',async()=>{
  const a=app();
  a.scope.crypto=undefined;
  a.$('devicePassword').value='private-password';
  await assert.rejects(a.run("startDeviceSession('dev_test', $('devicePassword'))"),/HTTPS o localhost/);
  assert.equal(a.$('devicePassword').value,'');
  assert.equal(a.ws.sent.length,0);
});
