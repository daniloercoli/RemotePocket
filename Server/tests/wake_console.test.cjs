const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function app() {
  class Element {
    constructor() { this.children=[]; this.dataset={}; this.value=''; this.hidden=false; this.fields=new Map(); }
    set textContent(value) { this.text=value; this.children=[]; }
    get textContent() { return this.text || ''; }
    set innerHTML(value) { this.html=value; this.querySelector('[data-wake-panel]').hidden=true; }
    querySelector(selector) { if (!this.fields.has(selector)) this.fields.set(selector,new Element()); return this.fields.get(selector); }
    appendChild(child) { this.children.push(child); }
    insertBefore(child, before) { this.children=this.children.filter(item=>item!==child); const i=this.children.indexOf(before); this.children.splice(i<0?this.children.length:i,0,child); }
    remove() {} removeAttribute() {} setAttribute() {} focus() {this.focused=true;} select() {this.selected=true;}
  }
  const elements=new Map(), copied=[];
  const get=id=>{if(!elements.has(id)) elements.set(id,new Element());return elements.get(id);};
  const scope=vm.createContext({console, setInterval(){},setTimeout(){},clearTimeout(){},
    navigator:{clipboard:{async writeText(text){copied.push(text);}}},
    localStorage:{getItem(){return null;},setItem(){},removeItem(){}},
    location:{protocol:'https:',host:'localhost'},
    document:{hidden:false,getElementById:get,createElement(){return new Element();},querySelectorAll(){return [];}},
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../app/static/console.js'),'utf8'),scope);
  vm.runInContext("state.token='owner'; renderDevices([{id:'dev_test',name:'Phone',status:'offline',connection_mode:'on_demand',wake_configured:true}]);",scope);
  const card=get('devices').children[0];
  scope.testCard=card;
  return {scope,card,copied,get,run:code=>vm.runInContext(code,scope)};
}

test('offline device offers SMS/Telegram wake while session remains disabled',()=>{
  const a=app();
  assert.equal(a.card.querySelector('[data-wake]').disabled,false);
  assert.equal(a.card.querySelector('[data-start]').disabled,true);
  assert.match(a.card.querySelector('[data-mode]').textContent,/su richiesta/);
});

test('manual command can be copied, expires and does not open a session',async()=>{
  const a=app();
  let sent;
  a.scope.postJson=async (url,body)=>{sent={url,body};return {message:'RPW1 signed test command',expires_at:new Date(Date.now()+600000).toISOString()};};
  await a.run("generateWakeMessage('dev_test',testCard)");
  assert.equal(sent.url,'/api/devices/dev_test/wake-message');
  assert.equal(a.card.querySelector('[data-wake-panel]').hidden,false);
  await a.run('copyWakeMessage(testCard)');
  assert.deepEqual(a.copied,['RPW1 signed test command']);
  assert.equal(a.card.querySelector('[data-start]').disabled,true);
  a.card.querySelector('[data-wake-panel]').dataset.expires='0';
  await a.run('copyWakeMessage(testCard)');
  assert.equal(a.copied.length,1);
  assert.match(a.card.querySelector('[data-wake-status]').textContent,/scaduto/);
});

test('presence event enables existing authenticated session flow and revoke clears command',async()=>{
  const a=app();
  a.run("handleWsMessage({type:'device_changed',device:{...state.devices[0],status:'online'}})");
  assert.equal(a.card.querySelector('[data-start]').disabled,false);
  a.card.querySelector('[data-wake-message]').value='signed command';
  a.run("handleWsMessage({type:'device_changed',device:{...state.devices[0],status:'revoked',revoked_at:'now'}})");
  assert.equal(a.card.querySelector('[data-wake]').disabled,true);
  assert.equal(a.card.querySelector('[data-wake-message]').value,'');
});

test('late wake generation after logout cannot restore a command',async()=>{
  const a=app();
  let resolve;
  a.scope.postJson=()=>new Promise(done=>{resolve=done;});
  const pending=a.run("generateWakeMessage('dev_test',testCard)");
  a.run("state.authEpoch++; state.token=''; state.devices=[];");
  resolve({message:'do not display',expires_at:new Date(Date.now()+600000).toISOString()});
  await pending;
  assert.equal(a.card.querySelector('[data-wake-message]').value,'');
});

test('clipboard failure selects the message for manual copying',async()=>{
  const a=app();
  a.card.querySelector('[data-wake-message]').value='signed command';
  a.card.querySelector('[data-wake-panel]').dataset.expires=String(Date.now()+60000);
  a.scope.navigator.clipboard.writeText=async()=>{throw new Error('denied');};
  await a.run('copyWakeMessage(testCard)');
  assert.equal(a.card.querySelector('[data-wake-message]').selected,true);
});
