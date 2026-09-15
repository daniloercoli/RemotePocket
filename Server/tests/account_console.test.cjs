const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
function app(hash = '', options = {}) {
  const elements = new Map(), requests = [], replacements = [], revoked = [], sockets = [], timers = [], intervals = [], storage = options.sharedStorage || new Map(Object.entries(options.storage || {}));
  const events = new Map();
  let nextTimer = 0;
  const element = () => ({value:'',_text:'',children:[],dataset:{},
    get textContent(){return this._text;},set textContent(value){this._text=value;this.children=[];},
    focus(){},appendChild(child){this.children.push(child);},removeAttribute(name){delete this[name];},setAttribute(){}});
  const $ = id => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
  const scope = vm.createContext({URLSearchParams, Blob,
    navigator:{locks:options.locks || {request:(_name, work)=>work()}},
    addEventListener:(name, callback)=>events.set(name, callback),
    location:{hash,pathname:'/',search:'',protocol:'http:',host:'localhost'}, history:{replaceState(...args){replacements.push(args);}},
    localStorage:{removeItem(key){storage.delete(key);},getItem(key){return storage.get(key);},setItem(key,value){storage.set(key,value);}},
    setInterval(callback,delay){intervals.push({callback,delay});},setTimeout(callback,delay){callback.id=++nextTimer;callback.delay=delay;timers.push(callback);return callback.id;},
    clearTimeout(id){const index=timers.findIndex(callback=>callback.id===id);if(index>=0)timers.splice(index,1);},
    WebSocket:class {constructor(){sockets.push(this);}close(){}send(){}},
    URL:{createObjectURL(){return 'blob:test';},revokeObjectURL(url){revoked.push(url);}},
    fetch:async(url,options)=>{
      if (url === '/api/auth/config') return {ok:true,json:async()=>({bootstrap_available:true,email_available:true,totp_available:true})};
      requests.push({url,body:options.body && JSON.parse(options.body),headers:options.headers});
      return {ok:true,json:async()=>({message:'OK',devices:[]})};
    },
    document:{hidden:false,getElementById:$,createElement:element,querySelectorAll:()=>[]}, console,
  });
  if (options.fetch) scope.fetch=options.fetch;
  for (const file of ['console.js','account.js']) vm.runInContext(fs.readFileSync(path.join(__dirname,'../app/static',file),'utf8'),scope);
  return {$,scope,requests,replacements,revoked,sockets,timers,intervals,storage,events,run:code=>vm.runInContext(code,scope)};
}
const deferred = () => { let resolve; const promise = new Promise(done=>{resolve=done;}); return {promise,resolve}; };
const tick = () => new Promise(setImmediate);
test('opening email links removes the fragment without consuming the token', async()=>{
  const a=app('#verify=disposable-test-token');
  assert.equal(a.replacements[0][2],'/');
  assert.equal(a.$('consumeVerify').hidden,false);
  assert.equal(a.$('recoveryPanel').open,true);
  assert.equal(a.requests.length,0);
  await a.$('consumeVerify').onclick();
  assert.equal(a.requests[0].url,'/api/auth/email-verify');
  assert.equal(a.requests[0].body.token,'disposable-test-token');
  assert.equal(a.$('consumeVerify').hidden,true);
});
test('reset is explicit, clears password and tokens only after success',async()=>{
  const a=app('#reset=test-reset'); a.$('newPassword').value='new-test-password';
  assert.equal(a.requests.length,0);
  await a.$('consumeReset').onclick();
  assert.equal(a.requests[0].body.new_password,'new-test-password');
  assert.equal(a.$('newPassword').value,'');
  assert.equal(a.$('consumeReset').hidden,true);
});
test('failed reset keeps the link available and displays a contextual error',async()=>{
  const a=app('#reset=expired');
  a.scope.postJson=async()=>{throw new Error('Token scaduto');};
  await a.$('consumeReset').onclick();
  assert.equal(a.$('consumeReset').hidden,false);
  assert.equal(a.$('recoveryStatus').textContent,'Token scaduto');
});

test('logout immediately removes account data, secrets, QR and persisted credentials',async()=>{
  const a=app();
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); state.challenge='challenge';");
  const post=a.run('postJson');
  a.scope.postJson=async(url,...args)=>url.endsWith('/setup') ? {secret:'manual-secret',qr_svg:'<svg/>'} : post(url,...args);
  a.$('currentPassword').value='private-password';
  await a.$('setupMfa').onclick();
  assert.equal(a.$('qrImage').src,'blob:test');
  for (const id of ['factorCode','loginCode','newEmail','newPassword','activityDevice']) a.$(id).value='private';
  for (const id of ['recoveryCodes','accountStatus','activityEvents','activitySummary']) a.$(id).textContent='private';
  a.run("state.devices=[{name:'private'}]; activityCursor='private-cursor';");
  const pending=deferred();
  a.scope.fetch=()=>pending.promise;
  const logout=a.run('logout()');
  assert.equal(a.run('state.token'),'');
  assert.equal(a.run('state.challenge'),'');
  assert.equal(a.run('state.devices.length'),0);
  assert.equal(a.run('activityCursor'),null);
  assert.equal(a.storage.size,0);
  for (const id of ['currentPassword','factorCode','loginCode','newEmail','newPassword','activityDevice']) assert.equal(a.$(id).value,'',id);
  for (const id of ['manualSecret','recoveryCodes','accountStatus','activityEvents','activitySummary']) assert.equal(a.$(id).textContent,'',id);
  assert.equal(a.$('qrImage').src,undefined);
  assert.equal(a.$('qrImage').hidden,true);
  assert.deepEqual(a.revoked,['blob:test']);
  pending.resolve({ok:true,json:async()=>({})}); await logout;
});

test('MFA recovery codes survive the intentional credential reset and clear on dismissal or logout',async()=>{
  const a=app();
  a.scope.postJson=async()=>({recovery_codes:['one-time-code']});
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'});");
  await a.$('regenerateMfa').onclick();
  assert.equal(a.run('state.token'),'');
  assert.match(a.$('recoveryCodes').textContent,/one-time-code/);
  a.$('dismissCodes').onclick();
  assert.equal(a.$('recoveryCodes').textContent,'');
  await a.$('regenerateMfa').onclick();
  await a.run('logout()');
  assert.equal(a.$('recoveryCodes').textContent,'');
});

for (const [id,endpoint] of [['confirmMfa','/api/auth/mfa/confirm'],['regenerateMfa','/api/auth/mfa/recovery-codes/regenerate']]) {
  for (const first of ['revocation','codes']) test(`${id} displays recovery codes when ${first} arrives first`,async()=>{
    const a=app(), codes=deferred(), refresh=deferred(); let mutations=0;
    a.scope.fetch=async url=>{
      if (url===endpoint) { mutations++; return codes.promise; }
      if (url==='/api/auth/refresh') return refresh.promise;
      return response();
    };
    a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); connectConsoleWs();");
    const ws=a.sockets[0]; ws.onopen();
    const operation=a.$(id).onclick();
    ws.onclose({code:4001});
    if (first==='revocation') {
      refresh.resolve(response({detail:'Session revoked'},401)); await tick();
      assert.equal(a.run('state.token'),'');
      assert.equal(a.storage.size,0);
    }
    codes.resolve(response({recovery_codes:['new-one-time-code']})); await operation;
    if (first==='codes') {
      refresh.resolve(response({detail:'Session revoked'},401)); await tick();
    }
    // A queued callback from the revoked socket must not erase displayed codes.
    ws.onclose({code:4001}); await tick();
    assert.match(a.$('recoveryCodes').textContent,/new-one-time-code/);
    assert.equal(a.$('dismissCodes').hidden,false);
    assert.equal(a.run('state.token'),'');
    assert.equal(a.storage.size,0);
    assert.equal(a.timers.length,0);
    assert.equal(a.sockets.length,1);
    assert.equal(mutations,1);
  });

  for (const transition of ['logout','login','failed login']) test(`late ${id} codes stay hidden after automatic revocation followed by ${transition}`,async()=>{
    const a=app(), codes=deferred();
    a.scope.fetch=async url=>{
      if (url===endpoint) return codes.promise;
      if (url==='/api/auth/refresh') return response({detail:'Session revoked'},401);
      if (url==='/api/auth/login') return transition==='failed login'
        ? response({detail:'Invalid password'},401) : response({access_token:'new-owner',refresh_token:'new-refresh'});
      return response({devices:[]});
    };
    a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); connectConsoleWs();");
    a.sockets[0].onopen();
    const operation=a.$(id).onclick();
    a.sockets[0].onclose({code:4001}); await tick();
    assert.equal(a.run('state.token'),'');
    if (transition==='logout') await a.run('logout()');
    else {
      const login=a.run("login('/api/auth/login',{username:'new-owner',password:'password'})");
      if (transition==='failed login') await assert.rejects(login,/Invalid password/);
      else await login;
    }
    codes.resolve(response({recovery_codes:['obsolete-secret']})); await operation;
    assert.equal(a.$('recoveryCodes').textContent,'');
    assert.equal(a.$('dismissCodes').hidden,true);
    assert.equal(a.run('state.token'),transition==='login'?'new-owner':'');
    assert.equal(a.storage.get('mydesk.ownerToken'),transition==='login'?'new-owner':undefined);
    if (transition==='failed login') assert.equal(a.$('authStatus').textContent,'Invalid password');
  });
}

test('automatic session revocation still discards a pending MFA setup secret',async()=>{
  const a=app(), setup=deferred();
  a.scope.fetch=async url=>url==='/api/auth/mfa/setup' ? setup.promise : response({detail:'Session revoked'},401);
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); connectConsoleWs();");
  a.sockets[0].onopen();
  const operation=a.$('setupMfa').onclick();
  a.sockets[0].onclose({code:4001}); await tick();
  setup.resolve(response({secret:'obsolete-secret',qr_svg:'<svg/>'})); await operation;
  assert.equal(a.$('manualSecret').textContent,'');
  assert.equal(a.$('qrImage').src,undefined);
  assert.equal(a.$('confirmMfa').hidden,true);
});

for (const id of ['setupMfa','confirmMfa','regenerateMfa']) test(`late ${id} response cannot redisplay secrets after logout`,async()=>{
  const a=app(), pending=deferred();
  a.scope.postJson=()=>pending.promise;
  const operation=a.$(id).onclick();
  await a.run('logout()');
  pending.resolve({secret:'obsolete',qr_svg:'<svg/>',recovery_codes:['obsolete']});
  await operation;
  assert.equal(a.$('manualSecret').textContent,'');
  assert.equal(a.$('recoveryCodes').textContent,'');
  assert.equal(a.$('qrImage').src,undefined);
  assert.equal(a.$('confirmMfa').hidden,true);
});

test('late account and activity responses cannot restore data after logout',async()=>{
  const a=app(), pending=deferred();
  a.run("state.token='access';");
  a.scope.getJson=async url=>{
    await pending.promise;
    return url.includes('summary') ? {devices:7} : url.includes('activity')
      ? {events:[{created_at:new Date().toISOString(),details:{private:'data'}}],next_cursor:'private'}
      : {username:'old-owner',email:'private@example.com'};
  };
  const account=a.run('showAccount()'), activity=a.run('refreshActivity()');
  await a.run('logout()');
  pending.resolve();
  await Promise.all([account,activity]);
  for (const id of ['accountStatus','activityEvents','activitySummary']) assert.equal(a.$(id).textContent,'');
  assert.equal(a.$('activityEvents').children.length,0);
  assert.equal(a.run('activityCursor'),null);
});

function activityApp() {
  const a=app(), queries=[];
  a.run("state.token='access';");
  a.scope.getJson=async url=>{
    queries.push(url);
    if (url.startsWith('/api/activity/summary')) return {devices:1,connected_devices:0,active_sessions:0,sessions_started:0,authentication_failures:0};
    const params=new URL(url,'https://localhost').searchParams;
    const device=params.get('device_id')||'all', more=params.has('cursor');
    return {events:[{created_at:'2026-09-13T12:00:00Z',event_type:more?'older':'latest',device_id:device,details:{}}],next_cursor:more?null:`cursor-${device}`};
  };
  return {...a,queries,poll:()=>a.intervals.find(interval=>interval.delay===30000).callback()};
}

for (const [id,value] of [['activityDevice','device-B'],['activityType','login'],['activityStart','2026-09-12T10:00'],['activityEnd','2026-09-13T15:00']]) {
  test(`changing ${id} clears the previous history and starts without its cursor`,async()=>{
    const a=activityApp();
    await a.run('refreshActivity()');
    a.$(id).value=value; a.$(id).oninput?.();
    assert.equal(a.$('activityEvents').children.length,0);
    assert.equal(a.$('activitySummary').textContent,'');
    assert.equal(a.$('activityMore').hidden,true);
    await a.run('refreshActivity(true)');
    const params=new URL(a.queries.at(-2),'https://localhost').searchParams;
    assert.equal(params.has('cursor'),false);
    assert.equal(a.$('activityEvents').children.length,1);
  });
}

test('More detects a changed filter even without an input event',async()=>{
  const a=activityApp();
  await a.run('refreshActivity()');
  a.$('activityDevice').value='device-B';
  await a.run('refreshActivity(true)');
  const params=new URL(a.queries.at(-2),'https://localhost').searchParams;
  assert.equal(params.get('device_id'),'device-B');
  assert.equal(params.has('cursor'),false);
  assert.equal(a.$('activityEvents').children.length,1);
  assert.match(a.$('activityEvents').children[0].textContent,/device-B/);
});

test('history polling pauses on later pages and resumes after an explicit refresh',async()=>{
  const a=activityApp();
  await a.run('refreshActivity()');
  await a.run('refreshActivity(true)');
  assert.equal(a.$('activityEvents').children.length,2);
  assert.equal(a.$('activityMore').hidden,true); // Also preserve the last page.
  const queries=a.queries.length;
  await a.poll();
  assert.equal(a.queries.length,queries);
  assert.equal(a.$('activityEvents').children.length,2);
  await a.$('activityRefresh').onclick();
  assert.equal(a.$('activityEvents').children.length,1);
  const refreshed=a.queries.length;
  await a.poll();
  assert.equal(a.queries.length,refreshed+2);
});

test('changing filters resumes polling from the first page of the new selection',async()=>{
  const a=activityApp();
  await a.run('refreshActivity()'); await a.run('refreshActivity(true)');
  a.$('activityDevice').value='device-B'; a.$('activityDevice').onchange?.();
  await a.poll();
  const params=new URL(a.queries.at(-2),'https://localhost').searchParams;
  assert.equal(params.has('cursor'),false);
  assert.equal(params.get('device_id'),'device-B');
  assert.equal(a.$('activityEvents').children.length,1);
});

for (const failure of [false,true]) test(`an old history ${failure?'failure':'page'} cannot overwrite new filters`,async()=>{
  const a=activityApp(), pending=deferred(); const get=a.scope.getJson;
  await a.run('refreshActivity()');
  a.scope.getJson=async url=>{
    if (url.includes('cursor=')) { await pending.promise; if(failure) throw new Error('old filter failed'); }
    return get(url);
  };
  const more=a.$('activityMore').onclick();
  a.$('activityDevice').value='device-B'; a.$('activityDevice').oninput?.();
  await a.$('activityRefresh').onclick();
  pending.resolve(); await more;
  assert.equal(a.$('activityEvents').children.length,1);
  assert.match(a.$('activityEvents').children[0].textContent,/device-B/);
  assert.doesNotMatch(a.$('activityError').textContent,/old filter failed/);
  assert.equal(a.run('activityCursor'),'cursor-device-B');
});

for (const flow of ['login','mfa']) test(`late ${flow} tokens are revoked without undoing logout or replacing a newer login`,async()=>{
  for (const replacement of [false,true]) {
    const a=app(), pending=deferred();
    a.scope.postJson=()=>pending.promise;
    a.run("state.challenge='challenge';"); a.$('loginCode').value='123456';
    const operation=flow==='login' ? a.run("login('/api/auth/login')") : a.$('verifyMfaButton').onclick();
    await a.run('logout()');
    if (replacement) a.run("clearCredentials(); saveTokens({access_token:'new-owner',refresh_token:'new-refresh'});");
    pending.resolve({access_token:'late-access',refresh_token:'late-refresh'});
    await operation;
    assert.equal(a.run('state.token'),replacement?'new-owner':'');
    assert.equal(a.run('state.refreshToken'),replacement?'new-refresh':'');
    assert.equal(a.sockets.length,0);
    assert.equal(a.requests.length,1);
    assert.equal(a.requests[0].url,'/api/auth/logout');
    assert.equal(a.requests[0].headers.Authorization,'Bearer late-access');
    assert.equal(a.requests[0].body.refresh_token,'late-refresh');
    assert.equal(a.run('state.challenge'),'');
  }
});

test('late login challenge and registration do not restart authentication after logout',async()=>{
  for (const flow of ['challenge','registration']) {
    const a=app(), pending=deferred(); let calls=0;
    a.scope.postJson=()=>{calls++;return pending.promise;};
    const operation=flow==='challenge' ? a.run("login('/api/auth/login')") : a.$('registerButton').onclick();
    await a.run('logout()');
    pending.resolve({mfa_required:true,challenge_token:'late-challenge'});
    await operation;
    assert.equal(calls,1);
    assert.equal(a.run('state.challenge'),'');
    assert.equal(a.$('mfaLogin').hidden,true);
  }
});

test('logout revokes its captured session without clearing a newer login on completion',async()=>{
  const a=app(), pending=deferred(); const fetch=a.scope.fetch;
  a.scope.fetch=async(url,options)=>{ await pending.promise; return fetch(url,options); };
  a.run("saveTokens({access_token:'old-access',refresh_token:'old-refresh'});");
  const logout=a.run('logout()');
  a.run("saveTokens({access_token:'new-access',refresh_token:'new-refresh'});");
  pending.resolve(); await logout;
  assert.equal(a.run('state.token'),'new-access');
  assert.equal(a.requests[0].headers.Authorization,'Bearer old-access');
});

test('each established WebSocket can refresh a subsequently expired access token',async()=>{
  const a=app(); let refreshes=0;
  a.scope.postJson=async()=>({access_token:`access-${++refreshes}`,refresh_token:`refresh-${refreshes}`});
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); connectConsoleWs();");
  for (let i=0;i<2;i++) {
    a.sockets[i].onopen();
    a.sockets[i].onclose({code:4001});
    await tick();
    assert.equal(refreshes,i+1);
    assert.equal(a.sockets.length,i+2);
  }
});

test('an explicit authentication denial after refresh stops reconnecting',async()=>{
  const a=app(); let refreshes=0;
  a.scope.postJson=async()=>({access_token:`access-${++refreshes}`,refresh_token:'refresh'});
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); connectConsoleWs();");
  a.sockets[0].onclose({code:1006}); await tick();
  a.sockets[1].onclose({code:4401}); await tick();
  assert.equal(refreshes,1);
  assert.equal(a.sockets.length,2);
  assert.equal(a.timers.length,0);
});

test('transient handshake failures keep backoff after a successful refresh and recover',async()=>{
  const a=app(); let refreshes=0;
  a.scope.postJson=async()=>({access_token:`access-${++refreshes}`,refresh_token:'refresh'});
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); connectConsoleWs();");
  a.sockets[0].onopen(); a.sockets[0].onclose({code:1006});
  assert.equal(a.timers[0].delay,1000); a.timers.shift()();
  a.sockets.at(-1).onclose({code:1006}); await tick();
  assert.equal(refreshes,1);
  for (const delay of [2000,4000,8000,16000,30000,30000]) {
    a.sockets.at(-1).onclose({code:1006}); await tick();
    assert.equal(a.timers.length,1);
    assert.equal(a.timers[0].delay,delay);
    a.timers.shift()();
  }
  assert.equal(refreshes,1);
  a.sockets.at(-1).onopen();
  assert.equal(a.$('connectionBadge').textContent,'console connessa');
  a.sockets.at(-1).onclose({code:4001}); await tick();
  assert.equal(refreshes,2);
});

for (const status of [429,503]) test(`temporary refresh failure ${status ?? 'network'} retries with backoff`,async()=>{
  const a=app(); let refreshes=0;
  a.scope.postJson=async()=>{
    if (++refreshes===1) throw Object.assign(new Error('temporary failure'),{status});
    return {access_token:'renewed',refresh_token:'renewed-refresh'};
  };
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); connectConsoleWs();");
  a.sockets[0].onclose({code:1006}); await tick();
  assert.equal(a.run('state.token'),'access');
  assert.equal(a.timers.length,1);
  assert.equal(a.timers[0].delay,1000);
  a.timers.shift()(); a.sockets.at(-1).onclose({code:1006}); await tick();
  assert.equal(refreshes,2);
  a.sockets.at(-1).onopen();
  assert.equal(a.run('state.token'),'renewed');
});

for (const status of [401,403]) test(`refresh authentication denial ${status} clears credentials and stops`,async()=>{
  const a=app();
  a.scope.postJson=async()=>{throw Object.assign(new Error('denied'),{status});};
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); connectConsoleWs();");
  a.sockets[0].onclose({code:1006}); await tick();
  assert.equal(a.timers.length,0);
  assert.equal(a.run('state.token'),'');
  assert.equal(a.storage.size,0);
});

test('logout cancels a scheduled reconnect and an already queued callback cannot reconnect',async()=>{
  const a=app();
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); connectConsoleWs();");
  a.sockets[0].onopen(); a.sockets[0].onclose({code:1006});
  const callback=a.timers[0];
  await a.run('logout()');
  assert.equal(a.timers.length,0);
  callback();
  assert.equal(a.sockets.length,1);
});

const storedTokens={'mydesk.ownerToken':'stored-access','mydesk.refreshToken':'stored-refresh'};
const response=(data={},status=200)=>({ok:status>=200&&status<300,status,json:async()=>data});
for (const status of [401,500]) test(`startup error ${status} arriving after a new login preserves the new credentials`,async()=>{
  const pending=deferred(); let deviceRequests=0;
  const a=app('',{storage:storedTokens,fetch:async url=>{
    if (url==='/api/devices' && ++deviceRequests===1) return pending.promise;
    if (url==='/api/auth/login') return response({access_token:'new-access',refresh_token:'new-refresh'});
    return response({devices:[]});
  }});
  await a.run('logout()');
  await a.run("login('/api/auth/login',{username:'new-owner',password:'new-password'})");
  pending.resolve(response({detail:'old failure'},status)); await tick();
  assert.equal(a.run('state.token'),'new-access');
  assert.equal(a.storage.get('mydesk.ownerToken'),'new-access');
  assert.equal(a.storage.get('mydesk.refreshToken'),'new-refresh');
});

for (const status of [undefined,500]) test(`temporary startup error ${status ?? 'network'} preserves the current credentials`,async()=>{
  const a=app('',{storage:storedTokens,fetch:async url=>{
    if (url!=='/api/devices') return response();
    if (status===undefined) throw new Error('network failure');
    return response({detail:'temporary failure'},status);
  }});
  await tick();
  assert.equal(a.run('state.token'),'stored-access');
  assert.equal(a.storage.get('mydesk.ownerToken'),'stored-access');
  assert.equal(a.storage.get('mydesk.refreshToken'),'stored-refresh');
});

test('startup authentication failure clears both memory and storage when refresh is denied',async()=>{
  const a=app('',{storage:storedTokens,fetch:async url=>url==='/api/auth/config' ? response() : response({detail:'denied'},401)});
  await tick();
  assert.equal(a.run('state.token'),'');
  assert.equal(a.run('state.refreshToken'),'');
  assert.equal(a.storage.size,0);
  assert.equal(a.run('state.ws'),null);
});

for (const action of ['reset','verify']) test(`expired stored authentication preserves an opened ${action} email link`,async()=>{
  const requests=[];
  const a=app(`#${action}=email-link-token`,{storage:storedTokens,fetch:async(url,options)=>{
    if (url==='/api/auth/config') return response();
    if (url==='/api/auth/password-reset' || url==='/api/auth/email-verify') {
      requests.push({url,body:JSON.parse(options.body)}); return response();
    }
    return response({detail:'expired'},401);
  }});
  a.$('newPassword').value='replacement-password';
  await tick();
  assert.equal(a.storage.size,0);
  const button=action==='reset'?'consumeReset':'consumeVerify';
  assert.equal(a.$(button).hidden,false);
  await a.$(button).onclick();
  assert.equal(requests[0].body.token,'email-link-token');
  if (action==='reset') assert.equal(requests[0].body.new_password,'replacement-password');
  assert.equal(a.$(button).hidden,true);
});

for (const action of ['reset','verify']) test(`a pending ${action} confirmation completes across automatic session expiry`,async()=>{
  const a=app(`#${action}=email-link-token`), pending=deferred();
  a.scope.postJson=()=>pending.promise;
  a.$('newPassword').value='replacement-password';
  const button=action==='reset'?'consumeReset':'consumeVerify';
  const operation=a.$(button).onclick();
  a.run("clearCredentials('Accedi nuovamente.',{automatic:true})");
  pending.resolve({}); await operation;
  assert.equal(a.$(button).hidden,true);
  assert.match(a.$('recoveryStatus').textContent,/Password aggiornata|Operazione completata/);
});

for (const action of ['reset','verify']) test(`a pending ${action} confirmation cannot alter a newer login`,async()=>{
  const a=app(`#${action}=email-link-token`), pending=deferred();
  a.scope.postJson=()=>pending.promise;
  const button=action==='reset'?'consumeReset':'consumeVerify';
  const operation=a.$(button).onclick();
  a.run("clearCredentials(); saveTokens({access_token:'new-owner',refresh_token:'new-refresh'});");
  pending.resolve({}); await operation;
  assert.equal(a.run('state.token'),'new-owner');
  assert.equal(a.$('recoveryStatus').textContent,'');
});

test('successful registration and MFA login retain their captured input through cleanup',async()=>{
  const a=app(), bodies=[];
  a.scope.postJson=async(url,body)=>{
    bodies.push({url,body});
    if (url.endsWith('/register')) return {};
    if (url.endsWith('/login')) return {mfa_required:true,challenge_token:'current-challenge'};
    return {access_token:'access',refresh_token:'refresh'};
  };
  a.$('username').value='owner'; a.$('password').value='password'; a.$('email').value='owner@example.com';
  await a.$('registerButton').onclick();
  assert.equal(bodies[0].body.username,'owner');
  assert.equal(bodies[1].body.password,'password');
  assert.equal(a.run('state.challenge'),'current-challenge');
  a.$('loginCode').value='123456';
  await a.$('verifyMfaButton').onclick();
  assert.equal(bodies[2].body.challenge_token,'current-challenge');
  assert.equal(bodies[2].body.code,'123456');
  assert.equal(a.run('state.token'),'access');
  assert.equal(a.$('loginCode').value,'');
  assert.equal(a.$('mfaLogin').hidden,true);
  assert.equal(a.sockets.length,1);
});

test('an obsolete refresh cannot clear the promise or credentials of a newer refresh',async()=>{
  const a=app(), old=deferred(), current=deferred();
  a.scope.postJson=(_url,body)=>body.refresh_token==='old-refresh' ? old.promise : current.promise;
  a.run("saveTokens({access_token:'old',refresh_token:'old-refresh'});");
  const previous=a.run('refreshAuth()');
  a.run("clearCredentials(); saveTokens({access_token:'current',refresh_token:'current-refresh'});");
  const next=a.run('refreshAuth()'), nextPromise=a.run('state.refreshPromise');
  old.resolve({access_token:'obsolete',refresh_token:'obsolete-refresh'});
  await assert.rejects(previous,/Autenticazione sostituita/);
  assert.equal(a.run('state.refreshPromise'),nextPromise);
  assert.equal(a.run('state.token'),'current');
  current.resolve({access_token:'renewed',refresh_token:'renewed-refresh'});
  await next;
  assert.equal(a.run('state.token'),'renewed');
  assert.equal(a.run('state.refreshPromise'),null);
});

test('a pairing code received after logout is not displayed',async()=>{
  const a=app(), pending=deferred();
  a.scope.postJson=()=>pending.promise;
  const operation=a.$('pairingButton').onclick();
  await a.run('logout()');
  pending.resolve({code:'private-pairing-code',expires_at:'later'});
  await operation;
  assert.equal(a.$('pairingCode').textContent,'Nessun codice generato.');
});


function sharedAuthTabs() {
  const sharedStorage = new Map();
  let tail = Promise.resolve();
  const locks = {request(_name, work) {
    const result = tail.then(work);
    tail = result.catch(() => {});
    return result;
  }};
  const first = app('', {sharedStorage, locks});
  first.run("saveTokens({access_token:'access-0',refresh_token:'refresh-0',session_id:'login-session'});");
  const second = app('', {sharedStorage, locks});
  return {first, second, sharedStorage};
}

test('two tabs serialize refresh and share the rotated tokens without replay', async () => {
  const {first, second} = sharedAuthTabs();
  const pending = deferred(); let refreshes = 0;
  for (const tab of [first, second]) tab.scope.postJson = async (_url, body) => {
    assert.equal(body.refresh_token, 'refresh-0'); refreshes++;
    return pending.promise;
  };
  const requests = [first.run('refreshAuth()'), second.run('refreshAuth()')];
  await tick();
  assert.equal(refreshes, 1);
  pending.resolve({access_token:'access-1', refresh_token:'refresh-1', session_id:'login-session'});
  await Promise.all(requests);
  assert.equal(refreshes, 1);
  for (const tab of [first, second]) assert.equal(tab.run('state.refreshToken'), 'refresh-1');
});

test('storage events synchronize rotation and logout without adopting another account', () => {
  const {first, second, sharedStorage} = sharedAuthTabs();
  const notify = () => second.events.get('storage')({key:'mydesk.auth'});
  first.run("saveTokens({access_token:'access-1',refresh_token:'refresh-1',session_id:'login-session'});");
  notify(); assert.equal(second.run('state.token'), 'access-1');
  first.run("clearCredentials(); saveTokens({access_token:'different-account',refresh_token:'different-refresh',session_id:'different-login'});");
  notify(); assert.equal(second.run('state.token'), '');
  assert.equal(JSON.parse(sharedStorage.get('mydesk.auth')).access_token, 'different-account');
  first.run('clearCredentials()'); notify();
  assert.equal(sharedStorage.size, 0);
});

test('a tab waiting for the refresh lock cannot overwrite a replacement login', async () => {
  const {first, second, sharedStorage} = sharedAuthTabs();
  const pending = deferred();
  first.scope.postJson = () => pending.promise;
  const rotating = first.run('refreshAuth()');
  const waiting = second.run('refreshAuth()');
  const rejected = Promise.all([assert.rejects(rotating, /Autenticazione sostituita/), assert.rejects(waiting, /Sessione modificata|Autenticazione sostituita/)]);
  await tick();
  second.run("clearCredentials(); saveTokens({access_token:'replacement',refresh_token:'replacement-refresh',session_id:'replacement-login'});");
  pending.resolve({access_token:'obsolete',refresh_token:'obsolete-refresh',session_id:'login-session'});
  await rejected;
  assert.equal(JSON.parse(sharedStorage.get('mydesk.auth')).access_token, 'replacement');
  assert.equal(second.run('state.token'), 'replacement');
});

test('a lost refresh response is never retried by this or another tab', async () => {
  const {first, second} = sharedAuthTabs(); let refreshes = 0;
  for (const tab of [first, second]) tab.scope.postJson = async () => { refreshes++; throw new Error('response lost'); };
  await assert.rejects(first.run('refreshAuth()'), /Rinnovo non confermato/);
  await assert.rejects(second.run('refreshAuth()'), /Rinnovo non confermato/);
  await assert.rejects(first.run('refreshAuth()'), /Rinnovo non confermato/);
  assert.equal(refreshes, 1);
});

test('unsupported Web Locks requires login without replaying refresh credentials', async () => {
  const a = app(); let refreshes = 0;
  a.scope.navigator = {};
  a.scope.postJson = async () => { refreshes++; };
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'});");
  await assert.rejects(a.run('refreshAuth()'), /Rinnovo automatico non disponibile/);
  assert.equal(refreshes, 0);
});

test('logout in another tab prevents a pending refresh from restoring credentials', async () => {
  const {first, second, sharedStorage} = sharedAuthTabs();
  const pending = deferred(); let refreshes = 0;
  first.scope.postJson = () => { refreshes++; return pending.promise; };
  const rotating = first.run('refreshAuth()');
  const rejected = assert.rejects(rotating, /Autenticazione sostituita/);
  await tick();
  await second.run('logout()');
  pending.resolve({access_token:'late',refresh_token:'late-refresh',session_id:'login-session'});
  await rejected;
  assert.equal(refreshes, 1);
  assert.equal(sharedStorage.size, 0);
  assert.equal(first.run('state.token'), '');
  assert.equal(second.run('state.token'), '');
});

test('WebSocket quota denial keeps increasing backoff without refreshing tokens', async () => {
  const a = app(); let refreshes = 0;
  a.scope.postJson = async () => { refreshes++; };
  a.run("saveTokens({access_token:'access',refresh_token:'refresh'}); connectConsoleWs();");
  for (const delay of [5000, 10000, 20000, 30000]) {
    a.sockets.at(-1).onopen();
    a.sockets.at(-1).onclose({code:4429});
    assert.equal(a.timers[0].delay, delay);
    a.timers.shift()();
  }
  assert.equal(refreshes, 0);
  assert.equal(a.run('state.token'), 'access');
});
