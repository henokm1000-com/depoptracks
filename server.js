import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { google } from 'googleapis';

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = process.cwd();
const DATA = path.join(ROOT,'data');
const TOKEN_FILE = path.join(DATA,'gmail-token.json');
const ACCOUNTS_FILE = path.join(DATA,'accounts.json');
const SESSIONS_FILE = path.join(DATA,'sessions.json');
fs.mkdirSync(DATA,{recursive:true});
app.use(express.json({limit:'1mb'}));

const CLIENT_ID=process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET=process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI=process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/oauth2callback`;
const SCOPES=['https://www.googleapis.com/auth/gmail.readonly'];
let oauthState=null;

function client(){
  if(!CLIENT_ID||!CLIENT_SECRET) throw new Error('Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in .env');
  return new google.auth.OAuth2(CLIENT_ID,CLIENT_SECRET,REDIRECT_URI);
}
function saveToken(t){fs.writeFileSync(TOKEN_FILE,JSON.stringify(t,null,2),'utf8');}
function loadToken(){try{return JSON.parse(fs.readFileSync(TOKEN_FILE,'utf8'));}catch{return null;}}
function gmailClient(){const c=client();const t=loadToken();if(!t) return null;c.setCredentials(t);return {auth:c,gmail:google.gmail({version:'v1',auth:c})};}

// ── Real account system ────────────────────────────────────────────────────
// Accounts and tracker data are stored on the server. The browser only keeps
// a login token, so sales/costs can be shared between devices.
function readJson(file,fallback){try{return JSON.parse(fs.readFileSync(file,'utf8'));}catch{return fallback;}}
function writeJson(file,value){const tmp=file+'.tmp';fs.writeFileSync(tmp,JSON.stringify(value,null,2),'utf8');fs.renameSync(tmp,file);}
function loadAccounts(){return readJson(ACCOUNTS_FILE,{});}
function saveAccounts(v){writeJson(ACCOUNTS_FILE,v);}
function loadSessions(){return readJson(SESSIONS_FILE,{});}
function saveSessions(v){writeJson(SESSIONS_FILE,v);}
function hashPassword(password,salt){return crypto.scryptSync(password,salt,64).toString('hex');}
function makeToken(){return crypto.randomBytes(32).toString('hex');}
function cleanUsername(v){return String(v||'').trim().toLowerCase().replace(/[^a-z0-9_]/g,'');}
function createSession(username){const token=makeToken();const sessions=loadSessions();sessions[token]={username,expiresAt:Date.now()+1000*60*60*24*30};saveSessions(sessions);return token;}
function getUser(req){const token=String(req.headers.authorization||'').replace(/^Bearer\s+/i,'');if(!token)return null;const sessions=loadSessions();const s=sessions[token];if(!s)return null;if(s.expiresAt<Date.now()){delete sessions[token];saveSessions(sessions);return null;}return s.username;}
function userDataFile(username,key){return path.join(DATA,`user-${username}-${key}.json`);}
function allowedKey(key){return key==='sales'||key==='goals'||key==='fulfillment';}

app.post('/api/auth/signup',(req,res)=>{
  try{
    const username=cleanUsername(req.body?.username);const password=String(req.body?.password||'');
    if(username.length<2)return res.status(400).json({error:'Username must be at least 2 characters.'});
    if(password.length<4)return res.status(400).json({error:'Password must be at least 4 characters.'});
    const accounts=loadAccounts();if(accounts[username])return res.status(409).json({error:'Username already taken.'});
    const salt=crypto.randomBytes(16).toString('hex');accounts[username]={salt,hash:hashPassword(password,salt),created:Date.now()};saveAccounts(accounts);
    res.json({ok:true,token:createSession(username),username});
  }catch(e){res.status(500).json({error:e.message});}
});

// Used only to move an old browser-only account onto the server.
app.post('/api/auth/migrate',(req,res)=>{
  try{
    const username=cleanUsername(req.body?.username);const legacyHash=String(req.body?.legacyHash||'');
    if(username.length<2||!legacyHash)return res.status(400).json({error:'Invalid migration data.'});
    const accounts=loadAccounts();
    if(accounts[username])return res.status(409).json({error:'Account already exists on the server.'});
    accounts[username]={legacyHash,created:Date.now(),migrated:true};saveAccounts(accounts);
    res.json({ok:true,token:createSession(username),username});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/auth/login',(req,res)=>{
  try{
    const username=cleanUsername(req.body?.username);const password=String(req.body?.password||'');const accounts=loadAccounts();const account=accounts[username];
    if(!account)return res.status(404).json({error:'No account found.'});
    if(account.legacyHash){
      const legacy=crypto.createHash('sha256').update(username+':'+password).digest('hex');
      if(legacy!==account.legacyHash)return res.status(401).json({error:'Wrong password. Try again.'});
      const salt=crypto.randomBytes(16).toString('hex');account.salt=salt;account.hash=hashPassword(password,salt);delete account.legacyHash;saveAccounts(accounts);
    }else{
      const actual=Buffer.from(hashPassword(password,account.salt),'hex');const expected=Buffer.from(account.hash,'hex');
      if(actual.length!==expected.length||!crypto.timingSafeEqual(actual,expected))return res.status(401).json({error:'Wrong password. Try again.'});
    }
    res.json({ok:true,token:createSession(username),username});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/auth/logout',(req,res)=>{const token=String(req.headers.authorization||'').replace(/^Bearer\s+/i,'');if(token){const s=loadSessions();delete s[token];saveSessions(s);}res.json({ok:true});});
app.get('/api/auth/me',(req,res)=>{const username=getUser(req);if(!username)return res.status(401).json({error:'Not logged in.'});res.json({ok:true,username});});

app.get('/api/data/:key',(req,res)=>{
  const username=getUser(req);if(!username)return res.status(401).json({error:'Not logged in.'});const key=req.params.key;if(!allowedKey(key))return res.status(400).json({error:'Invalid data key.'});
  try{const file=userDataFile(username,key);res.json({value:fs.existsSync(file)?readJson(file,null):null});}catch(e){res.status(500).json({error:e.message});}
});
app.put('/api/data/:key',(req,res)=>{
  const username=getUser(req);if(!username)return res.status(401).json({error:'Not logged in.'});const key=req.params.key;if(!allowedKey(key))return res.status(400).json({error:'Invalid data key.'});
  try{writeJson(userDataFile(username,key),req.body?.value??null);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}
});

// ── Serve the existing frontend ────────────────────────────────────────────
// The account code in the old HTML used browser-only storage. Replace only
// that auth block while serving the existing UI, leaving the rest untouched.
function serveIndex(req,res){
  try{
    let html=fs.readFileSync(path.join(ROOT,'public','index.html'),'utf8');
    const authStart=html.indexOf('// ── Account / Auth System');
    const scriptEnd=authStart>=0?html.indexOf('</script>',authStart):-1;
    if(authStart>=0&&scriptEnd>=0){
      const newAuth=`// ── Server Account / Auth System ───────────────────────────────────────\n(function(){\n const SESSION_KEY='depop-session-v1';\n const TOKEN_KEY='depop-server-token-v1';\n const STORAGE_KEY='depop-tracker-v6';\n const GOAL_KEY='depop-tracker-goals-v1';\n const overlay=document.getElementById('auth-overlay');\n const tabLogin=document.getElementById('auth-tab-login');\n const tabSignup=document.getElementById('auth-tab-signup');\n const uInput=document.getElementById('auth-username');\n const pInput=document.getElementById('auth-password');\n const cInput=document.getElementById('auth-confirm');\n const cWrap=document.getElementById('auth-confirm-wrap');\n const submitBtn=document.getElementById('auth-submit');\n const msgEl=document.getElementById('auth-msg');\n const badge=document.getElementById('account-badge');\n const badgeName=document.getElementById('account-name');\n const badgeAvtr=document.getElementById('account-avatar');\n const logoutBtn=document.getElementById('account-logout');\n let mode='login';let currentUser=null;let syncing=false;\n function setMsg(txt,type){msgEl.textContent=txt;msgEl.className='auth-msg'+(type?' '+type:'');}\n function setMode(m){mode=m;tabLogin.classList.toggle('active',m==='login');tabSignup.classList.toggle('active',m==='signup');cWrap.classList.toggle('hidden',m==='login');submitBtn.textContent=m==='login'?'Log in':'Create account';setMsg('');uInput.focus();}\n async function api(url,opts={}){const headers={...(opts.headers||{}),'Content-Type':'application/json'};const token=localStorage.getItem(TOKEN_KEY);if(token)headers.Authorization='Bearer '+token;const r=await fetch(url,{...opts,headers});let data={};try{data=await r.json();}catch{}if(!r.ok)throw new Error(data.error||('Request failed ('+r.status+')'));return data;}\n function parseLocal(key,fallback){try{const x=JSON.parse(localStorage.getItem(key)||'');return x??fallback;}catch{return fallback;}}\n function saleMatch(a,b){if(a.id&&b.id&&a.id===b.id)return true;return String(a.itemName||a.item||'').trim().toLowerCase()===String(b.itemName||b.item||'').trim().toLowerCase()&&String(a.date||'')===String(b.date||'')&&Number(a.sold||0)===Number(b.sold||0);}\n function mergeSales(serverSales,localSales){\n   if(!Array.isArray(serverSales))serverSales=[];if(!Array.isArray(localSales))localSales=[];\n   const out=serverSales.map(s=>({...s}));\n   for(const l of localSales){const i=out.findIndex(s=>saleMatch(s,l));if(i<0){out.push(l);continue;}const s=out[i];\n     if((Number(s.cost)||0)<=0&&(Number(l.cost)||0)>0)s.cost=l.cost;\n     if((Number(s.fees)||0)<=0&&(Number(l.fees)||0)>0)s.fees=l.fees;\n     if((Number(s.sold)||0)<=0&&(Number(l.sold)||0)>0)s.sold=l.sold;\n     for(const k of ['notes','photo','image','imageData','buyer','status'])if((s[k]===undefined||s[k]===null||s[k]==='')&&l[k]!==undefined)s[k]=l[k];\n   }\n   return out;\n }\n async function loadUserData(){\n   const localSales=parseLocal(STORAGE_KEY,[]);const localGoals=parseLocal(GOAL_KEY,null);\n   let remoteSales=null,remoteGoals=null;\n   try{remoteSales=(await api('/api/data/sales')).value;}catch{}\n   try{remoteGoals=(await api('/api/data/goals')).value;}catch{}\n   const merged=mergeSales(remoteSales,localSales);\n   localStorage.setItem(STORAGE_KEY,JSON.stringify(merged));\n   if(remoteSales===null || JSON.stringify(remoteSales)!==JSON.stringify(merged))await api('/api/data/sales',{method:'PUT',body:JSON.stringify({value:merged})});\n   if(remoteGoals===null&&localGoals!==null){localStorage.setItem(GOAL_KEY,JSON.stringify(localGoals));await api('/api/data/goals',{method:'PUT',body:JSON.stringify({value:localGoals})});}\n   else if(remoteGoals!==null)localStorage.setItem(GOAL_KEY,JSON.stringify(remoteGoals));\n }\n async function loginUser(username,token){currentUser=username;localStorage.setItem(SESSION_KEY,username);if(token)localStorage.setItem(TOKEN_KEY,token);await loadUserData();badgeName.textContent=username;badgeAvtr.textContent=username.slice(0,1).toUpperCase();badge.classList.remove('hidden');overlay.classList.add('hidden');\n   // Reload once after server data has been placed into localStorage so the existing tracker reads the synced data.\n   if(sessionStorage.getItem('depop-server-hydrated')!=='1'){sessionStorage.setItem('depop-server-hydrated','1');location.reload();}\n }\n async function doAuth(){const username=String(uInput.value||'').trim().toLowerCase().replace(/[^a-z0-9_]/g,'');const password=String(pInput.value||'');if(username.length<2){setMsg('Please enter a username.','err');return;}if(password.length<4){setMsg('Password must be at least 4 characters.','err');return;}if(mode==='signup'&&password!==String(cInput.value||'')){setMsg('Passwords do not match.','err');return;}submitBtn.disabled=true;setMsg('');try{if(mode==='signup'){const r=await api('/api/auth/signup',{method:'POST',body:JSON.stringify({username,password})});await loginUser(r.username,r.token);return;}try{const r=await api('/api/auth/login',{method:'POST',body:JSON.stringify({username,password})});await loginUser(r.username,r.token);return;}catch(e){\n     // Migrate an old browser-only account once, if it exists on this device.\n     if(e.message!=='No account found.')throw e;\n     const raw=localStorage.getItem('ws:auth:'+username)||localStorage.getItem('auth:'+username);\n     if(!raw)throw e;let old;try{old=JSON.parse(raw);}catch{throw e;}\n     if(!old.hash)throw e;const r=await api('/api/auth/migrate',{method:'POST',body:JSON.stringify({username,legacyHash:old.hash})});await loginUser(r.username,r.token);\n   }}catch(e){setMsg(e.message||'Something went wrong.','err');}finally{submitBtn.disabled=false;submitBtn.textContent=mode==='login'?'Log in':'Create account';}}\n tabLogin.addEventListener('click',()=>setMode('login'));tabSignup.addEventListener('click',()=>setMode('signup'));[uInput,pInput,cInput].forEach(el=>el&&el.addEventListener('keydown',e=>{if(e.key==='Enter')doAuth();}));submitBtn.addEventListener('click',doAuth);\n logoutBtn.addEventListener('click',async()=>{if(!currentUser)return;if(!confirm('Log out of '+currentUser+'?'))return;try{await api('/api/auth/logout',{method:'POST'});}catch{}localStorage.removeItem(TOKEN_KEY);localStorage.removeItem(SESSION_KEY);sessionStorage.removeItem('depop-server-hydrated');currentUser=null;badge.classList.add('hidden');overlay.classList.remove('hidden');setMode('login');uInput.focus();});\n // Sync every sales/goal change made by the existing tracker to the server.\n const originalSet=localStorage.setItem.bind(localStorage);\n localStorage.setItem=function(key,value){originalSet(key,value);if(!currentUser||syncing)return;if(key!==STORAGE_KEY&&key!==GOAL_KEY)return;const data=String(value);const endpoint=key===STORAGE_KEY?'sales':'goals';api('/api/data/'+endpoint,{method:'PUT',body:JSON.stringify({value:JSON.parse(data)})}).catch(()=>{});};\n async function autoLogin(){const token=localStorage.getItem(TOKEN_KEY);const saved=localStorage.getItem(SESSION_KEY);if(token&&saved){try{await api('/api/auth/me');await loginUser(saved,null);return;}catch{localStorage.removeItem(TOKEN_KEY);}}overlay.classList.remove('hidden');setTimeout(()=>uInput.focus(),100);}\n autoLogin();\n})();`;
      html=html.slice(0,authStart)+newAuth+'\n'+html.slice(scriptEnd);
    }
    res.type('html').send(html);
  }catch(e){res.status(500).send('Unable to load tracker: '+e.message);}
}

app.get('/',serveIndex);
app.use(express.static(path.join(ROOT,'public')));

app.get('/api/gmail/status',(req,res)=>{const t=loadToken();res.json({connected:!!t,email:t?.email||null});});
app.get('/api/gmail/auth',(req,res)=>{try{const c=client();oauthState=crypto.randomBytes(24).toString('hex');const url=c.generateAuthUrl({access_type:'offline',prompt:'consent',scope:SCOPES,state:oauthState});res.json({url});}catch(e){res.status(500).json({error:e.message});}});
app.get('/oauth2callback',async(req,res)=>{try{if(!oauthState||req.query.state!==oauthState)return res.status(400).send('Invalid OAuth state. Start again from the website.');const c=client();const {tokens}=await c.getToken(req.query.code);c.setCredentials(tokens);const g=google.gmail({version:'v1',auth:c});const profile=await g.users.getProfile({userId:'me'});saveToken({...tokens,email:profile.data.emailAddress});res.send(`<html><body style="font-family:system-ui;background:#0d0d10;color:white;display:grid;place-items:center;height:100vh"><div><h2>Gmail connected</h2><p>You can close this tab and return to your tracker.</p><script>setTimeout(()=>window.location.href='/',1500)</script></div></body></html>`);}catch(e){res.status(500).send('Gmail connection failed: '+e.message);}});

function b64decode(s){if(!s)return '';return Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8');}
function collectParts(part,out){if(!part)return;if(part.mimeType==='text/plain'&&part.body?.data)out.push(b64decode(part.body.data));if(part.mimeType==='text/html'&&part.body?.data&&!out.length)out.push(b64decode(part.body.data).replace(/<[^>]+>/g,' '));for(const p of part.parts||[])collectParts(p,out);}
function header(headers,name){return (headers||[]).find(h=>h.name.toLowerCase()===name.toLowerCase())?.value||'';}
function money(v){const m=String(v||'').replace(/[$,]/g,'').match(/-?\d+(?:\.\d{1,2})?/);return m?Number(m[0]):0;}
function parseSale(text,headers){const clean=text.replace(/\r/g,' ');const subject=header(headers,'Subject');const item=(clean.match(/(?:item|listing|product)\s*(?:name|title)?\s*[:\-]\s*([^\n]{3,120})/i)||[])[1]||(subject.match(/(?:sold|sale)[:\-]?\s*(.+)$/i)||[])[1]||'Unknown item';const sold=(clean.match(/(?:sold for|sale price|item price|you sold)\s*[:\-]?\s*\$?([\d,.]+(?:\.\d{1,2})?)/i)||[])[1];const buyer=(clean.match(/(?:buyer|purchased by|username)\s*[:\-]?\s*@?([A-Za-z0-9_.-]{2,40})/i)||[])[1]||'—';const dateRaw=(clean.match(/(?:date of sale|sold on|order date)\s*[:\-]?\s*([^\n]{6,40})/i)||[])[1];const iso=dateRaw?new Date(dateRaw.trim()).toISOString().slice(0,10):new Date().toISOString().slice(0,10);return {id:'fo-'+crypto.randomUUID(),itemName:item.trim(),sold:money(sold),buyer:buyer.trim(),date:iso,status:'new',emailId:null,subject};}
app.post('/api/gmail/sync',async(req,res)=>{try{const c=gmailClient();if(!c)return res.status(401).json({error:'Gmail is not connected. Click Connect Gmail first.'});const q=req.body?.query||'newer_than:30d (Depop OR from:depop.com) in:anywhere';const list=await c.gmail.users.messages.list({userId:'me',q,maxResults:50});const orders=[];for(const m of list.data.messages||[]){const full=await c.gmail.users.messages.get({userId:'me',id:m.id,format:'full'});const headers=full.data.payload?.headers||[];const parts=[];collectParts(full.data.payload,parts);const sale=parseSale(parts.join('\n'),headers);sale.emailId=m.id;orders.push(sale);}res.json({orders,checked:list.data.messages?.length||0});}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/fulfillment/submit',async(req,res)=>{try{const url=process.env.FULFILLMENT_WEBHOOK_URL;if(!url)return res.status(503).json({error:'FULFILLMENT_WEBHOOK_URL is not configured.'});const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json',...(process.env.FULFILLMENT_WEBHOOK_SECRET?{'Authorization':'Bearer '+process.env.FULFILLMENT_WEBHOOK_SECRET}:{})},body:JSON.stringify(req.body)});const txt=await r.text();if(!r.ok)return res.status(r.status).json({error:txt.slice(0,500)});res.json({ok:true,response:txt.slice(0,1000)});}catch(e){res.status(500).json({error:e.message});}});

app.get(/.*/,serveIndex);
app.listen(PORT,'0.0.0.0',()=>console.log(`Depop Tracker running on port ${PORT}`));
