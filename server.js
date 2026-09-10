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
fs.mkdirSync(DATA,{recursive:true});
app.use(express.json({limit:'1mb'}));
app.use(express.static(path.join(ROOT,'public')));

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



// ── Account system ──────────────────────────────────────────────────────────
// Accounts and user data live on the server, so logging in on another device
// loads the same sales/goals/fulfillment data.
const ACCOUNTS_FILE = path.join(DATA, 'accounts.json');
const SESSIONS = new Map();

function loadAccounts(){
  try { return JSON.parse(fs.readFileSync(ACCOUNTS_FILE,'utf8')); }
  catch { return {}; }
}
function saveAccounts(accounts){
  const tmp = ACCOUNTS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(accounts,null,2), 'utf8');
  fs.renameSync(tmp, ACCOUNTS_FILE);
}
function hashPassword(password, salt){
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function makeToken(){ return crypto.randomBytes(32).toString('hex'); }
function getUser(req){
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i,'');
  const username = SESSIONS.get(token);
  return username || null;
}
function cleanUsername(value){
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9_]/g,'');
}

app.post('/api/auth/signup',(req,res)=>{
  try{
    const username=cleanUsername(req.body?.username);
    const password=String(req.body?.password || '');
    if(username.length<2) return res.status(400).json({error:'Username must be at least 2 characters.'});
    if(password.length<4) return res.status(400).json({error:'Password must be at least 4 characters.'});
    const accounts=loadAccounts();
    if(accounts[username]) return res.status(409).json({error:'Username already taken.'});
    const salt=crypto.randomBytes(16).toString('hex');
    accounts[username]={salt,hash:hashPassword(password,salt),created:Date.now()};
    saveAccounts(accounts);
    const token=makeToken(); SESSIONS.set(token,username);
    res.json({ok:true,token,username});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/auth/login',(req,res)=>{
  try{
    const username=cleanUsername(req.body?.username);
    const password=String(req.body?.password || '');
    const account=loadAccounts()[username];
    if(!account) return res.status(401).json({error:'No account found. Sign up first.'});
    const hash=hashPassword(password,account.salt);
    const a=Buffer.from(hash,'hex'), b=Buffer.from(account.hash,'hex');
    if(a.length!==b.length || !crypto.timingSafeEqual(a,b)) return res.status(401).json({error:'Wrong password. Try again.'});
    const token=makeToken(); SESSIONS.set(token,username);
    res.json({ok:true,token,username});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/auth/logout',(req,res)=>{
  const token=String(req.headers.authorization || '').replace(/^Bearer\s+/i,'');
  if(token) SESSIONS.delete(token);
  res.json({ok:true});
});

app.get('/api/auth/me',(req,res)=>{
  const username=getUser(req);
  if(!username) return res.status(401).json({error:'Not logged in.'});
  res.json({ok:true,username});
});

app.get('/api/data/:key',(req,res)=>{
  const username=getUser(req);
  if(!username) return res.status(401).json({error:'Not logged in.'});
  const allowed=new Set(['sales','goals','fulfillment']);
  if(!allowed.has(req.params.key)) return res.status(400).json({error:'Invalid data key.'});
  const file=path.join(DATA,`user-${username}-${req.params.key}.json`);
  try{
    const value=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):null;
    res.json({value});
  }catch(e){res.status(500).json({error:e.message});}
});

app.put('/api/data/:key',(req,res)=>{
  const username=getUser(req);
  if(!username) return res.status(401).json({error:'Not logged in.'});
  const allowed=new Set(['sales','goals','fulfillment']);
  if(!allowed.has(req.params.key)) return res.status(400).json({error:'Invalid data key.'});
  const file=path.join(DATA,`user-${username}-${req.params.key}.json`);
  try{
    const tmp=file+'.tmp';
    fs.writeFileSync(tmp,JSON.stringify(req.body?.value ?? null),'utf8');
    fs.renameSync(tmp,file);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/gmail/status',(req,res)=>{
  const t=loadToken();
  res.json({connected:!!t,email:t?.email||null});
});

app.get('/api/gmail/auth',(req,res)=>{
  try{
    const c=client();
    oauthState=crypto.randomBytes(24).toString('hex');
    const url=c.generateAuthUrl({access_type:'offline',prompt:'consent',scope:SCOPES,state:oauthState});
    res.json({url});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/oauth2callback',async(req,res)=>{
  try{
    if(!oauthState || req.query.state!==oauthState) return res.status(400).send('Invalid OAuth state. Start again from the website.');
    const c=client();
    const {tokens}=await c.getToken(req.query.code);
    c.setCredentials(tokens);
    const g=google.gmail({version:'v1',auth:c});
    const profile=await g.users.getProfile({userId:'me'});
    saveToken({...tokens,email:profile.data.emailAddress});
    res.send(`<html><body style="font-family:system-ui;background:#0d0d10;color:white;display:grid;place-items:center;height:100vh"><div><h2>Gmail connected</h2><p>You can close this tab and return to your tracker.</p><script>setTimeout(()=>window.location.href='/',1500)</script></div></body></html>`);
  }catch(e){res.status(500).send('Gmail connection failed: '+e.message);}
});

function b64decode(s){
  if(!s)return '';
  return Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8');
}
function collectParts(part,out){
  if(!part)return;
  if(part.mimeType==='text/plain' && part.body?.data) out.push(b64decode(part.body.data));
  if(part.mimeType==='text/html' && part.body?.data && !out.length) out.push(b64decode(part.body.data).replace(/<[^>]+>/g,' '));
  for(const p of part.parts||[]) collectParts(p,out);
}
function header(headers,name){return (headers||[]).find(h=>h.name.toLowerCase()===name.toLowerCase())?.value||'';}
function money(v){const m=String(v||'').replace(/[$,]/g,'').match(/-?\d+(?:\.\d{1,2})?/);return m?Number(m[0]):0;}
function parseSale(text, headers){
  const clean=text.replace(/\r/g,' ');
  const subject=header(headers,'Subject');
  const item=(clean.match(/(?:item|listing|product)\s*(?:name|title)?\s*[:\-]\s*([^\n]{3,120})/i)||[])[1]
    || (subject.match(/(?:sold|sale)[:\-]?\s*(.+)$/i)||[])[1] || 'Unknown item';
  const sold=(clean.match(/(?:sold for|sale price|item price|you sold)\s*[:\-]?\s*\$?([\d,.]+(?:\.\d{1,2})?)/i)||[])[1];
  const buyer=(clean.match(/(?:buyer|purchased by|username)\s*[:\-]?\s*@?([A-Za-z0-9_.-]{2,40})/i)||[])[1]||'—';
  const dateRaw=(clean.match(/(?:date of sale|sold on|order date)\s*[:\-]?\s*([^\n]{6,40})/i)||[])[1];
  const iso=dateRaw ? new Date(dateRaw.trim()).toISOString().slice(0,10) : new Date().toISOString().slice(0,10);
  return {id:'fo-'+crypto.randomUUID(),itemName:item.trim(),sold:money(sold),buyer:buyer.trim(),date:iso,status:'new',emailId:null,subject};
}

app.post('/api/gmail/sync',async(req,res)=>{
  try{
    const c=gmailClient();if(!c)return res.status(401).json({error:'Gmail is not connected. Click Connect Gmail first.'});
    const q=req.body?.query || 'newer_than:30d (Depop OR from:depop.com) in:anywhere';
    const list=await c.gmail.users.messages.list({userId:'me',q,maxResults:50});
    const orders=[];
    for(const m of list.data.messages||[]){
      const full=await c.gmail.users.messages.get({userId:'me',id:m.id,format:'full'});
      const headers=full.data.payload?.headers||[];const parts=[];collectParts(full.data.payload,parts);
      const text=parts.join('\n');
      const sale=parseSale(text,headers); sale.emailId=m.id; orders.push(sale);
    }
    res.json({orders,checked:list.data.messages?.length||0});
  }catch(e){res.status(500).json({error:e.message});}
});

// Optional generic fulfillment webhook. Keep secrets server-side.
app.post('/api/fulfillment/submit',async(req,res)=>{
  try{
    const url=process.env.FULFILLMENT_WEBHOOK_URL;
    if(!url)return res.status(503).json({error:'FULFILLMENT_WEBHOOK_URL is not configured.'});
    const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json',...(process.env.FULFILLMENT_WEBHOOK_SECRET?{'Authorization':'Bearer '+process.env.FULFILLMENT_WEBHOOK_SECRET}:{})},body:JSON.stringify(req.body)});
    const txt=await r.text(); if(!r.ok)return res.status(r.status).json({error:txt.slice(0,500)});
    res.json({ok:true,response:txt.slice(0,1000)});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/', (req, res) => {
  res.sendFile(path.join(ROOT, 'public', 'index.html'));
});

app.get(/.*/, (req, res) => {
  res.sendFile(path.join(ROOT, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Depop Tracker running on port ${PORT}`);
});
