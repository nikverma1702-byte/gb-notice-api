// Notice API with staff logins. All secrets come from environment variables (never put them in code).
const express=require('express'),cors=require('cors'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),rateLimit=require('express-rate-limit'),{Pool}=require('pg');
const {DATABASE_URL,JWT_SECRET,ADMIN_USER,ADMIN_PASS,ALLOWED_ORIGIN}=process.env;
if(!DATABASE_URL||!JWT_SECRET)throw new Error('Set DATABASE_URL and JWT_SECRET');
const db=new Pool({connectionString:DATABASE_URL,ssl:{rejectUnauthorized:false}});
const CATS=['Admission','Examination','Result','University','Scholarship','College'];
const app=express();app.set('trust proxy',1);app.use((q,s,n)=>q.path==='/media'?n():express.json({limit:'50kb'})(q,s,n));
app.use(cors({origin:(ALLOWED_ORIGIN||'').split(',').map(s=>s.trim()).filter(Boolean)}));
const auth=role=>(q,s,n)=>{try{q.u=jwt.verify((q.headers.authorization||'').replace('Bearer ',''),JWT_SECRET);if(role&&q.u.role!==role)return s.sendStatus(403);n()}catch{s.sendStatus(401)}};
const log=(u,a,w)=>db.query('insert into audit(who,act,what) values($1,$2,$3)',[u,a,w]).catch(console.error);
const wrap=f=>(q,s)=>f(q,s).catch(e=>{console.error(e);s.sendStatus(500)});
(async()=>{
 const cols=(await db.query("select column_name from information_schema.columns where table_name='notices'")).rows.map(r=>r.column_name);
 if(cols.length&&!['id','t','date','cat','descr','url','author'].every(x=>cols.includes(x))){const old='notices_old_'+Date.now();await db.query('alter table notices rename to '+old);console.log('Old notices table renamed to '+old)}
 await db.query(`create table if not exists staff(username text primary key,hash text not null,role text not null default 'staff');
 create table if not exists audit(id serial primary key,at timestamptz default now(),who text,act text,what text);
 create table if not exists notices(id serial primary key,t text not null,date date not null,cat text not null,descr text,url text,author text);
 create table if not exists media(id serial primary key,mime text not null,data bytea not null,at timestamptz default now());
 alter table notices add column if not exists img_id int`);
 if(ADMIN_USER&&ADMIN_PASS){const u=ADMIN_USER.trim().toLowerCase();
  await db.query("insert into staff values($1,$2,'admin') on conflict (username) do update set hash=excluded.hash,role='admin'",[u,await bcrypt.hash(ADMIN_PASS.trim(),12)]);
  await db.query("delete from staff where role='admin' and username<>$1",[u]);
  console.log('Admin account ready: '+u)}else console.log('ADMIN_USER / ADMIN_PASS not set');
})().catch(e=>{console.error(e);process.exit(1)});
const clean=b=>{const t=String(b.t||'').trim().slice(0,200),cat=CATS.includes(b.cat)?b.cat:'College',date=/^\d{4}-\d{2}-\d{2}$/.test(b.date)?b.date:new Date().toISOString().slice(0,10),
 url=/^https?:\/\//.test(b.url||'')?b.url.slice(0,500):null,img=Number.isInteger(+b.imgId)&&+b.imgId>0?+b.imgId:null;return t?{t,cat,date,descr:String(b.desc||'').slice(0,2000),url,img}:null};
const sweep=()=>db.query("delete from media where at<now()-interval '1 hour' and id not in (select img_id from notices where img_id is not null)").catch(console.error);
app.get('/',(q,s)=>s.send('ok'));
app.post('/login',rateLimit({windowMs:15*60*1000,max:10}),wrap(async(q,s)=>{
 const r=await db.query('select * from staff where username=$1',[String(q.body.username||'').trim().toLowerCase()]);const u=r.rows[0];
 if(!u||!(await bcrypt.compare(String(q.body.password||''),u.hash)))return s.status(401).json({});
 s.json({token:jwt.sign({u:u.username,role:u.role},JWT_SECRET,{expiresIn:'12h'}),role:u.role})}));
app.get('/notices',wrap(async(q,s)=>{const base=process.env.PUBLIC_URL||(q.protocol+'://'+q.get('host'));
 s.json((await db.query(`select id,t,to_char(date,'YYYY-MM-DD') as date,cat,descr as "desc",url,img_id as "imgId",case when img_id is null then null else $1::text||'/media/'||img_id::text end as img from notices order by date desc,id desc`,[base])).rows)}));
app.post('/media',auth(),express.json({limit:'1mb'}),wrap(async(q,s)=>{
 const m=/^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(String(q.body.data||''));if(!m)return s.sendStatus(400);
 const b=Buffer.from(m[1],'base64');if(b.length<100||b.length>700000||b[0]!==0xFF||b[1]!==0xD8)return s.sendStatus(400);
 const r=await db.query('insert into media(mime,data) values($1,$2) returning id',['image/jpeg',b]);log(q.u.u,'uploaded','image #'+r.rows[0].id);s.json({id:r.rows[0].id})}));
app.get('/media/:id',wrap(async(q,s)=>{const r=await db.query('select mime,data from media where id=$1',[+q.params.id||0]);if(!r.rows[0])return s.sendStatus(404);
 s.set({'Content-Type':r.rows[0].mime,'Cache-Control':'public, max-age=31536000, immutable','Cross-Origin-Resource-Policy':'cross-origin','X-Content-Type-Options':'nosniff'});s.send(r.rows[0].data)}));
app.post('/notices',auth(),wrap(async(q,s)=>{const n=clean(q.body);if(!n)return s.sendStatus(400);
 const r=await db.query('insert into notices(t,date,cat,descr,url,author,img_id) values($1,$2,$3,$4,$5,$6,$7) returning id',[n.t,n.date,n.cat,n.descr,n.url,q.u.u,n.img]);log(q.u.u,'added',n.t);s.json(r.rows[0])}));
app.put('/notices/:id',auth(),wrap(async(q,s)=>{const n=clean(q.body);if(!n)return s.sendStatus(400);
 await db.query('update notices set t=$1,date=$2,cat=$3,descr=$4,url=$5,img_id=$6 where id=$7',[n.t,n.date,n.cat,n.descr,n.url,n.img,+q.params.id]);sweep();log(q.u.u,'edited',n.t);s.json({})}));
app.delete('/notices/:id',auth(),wrap(async(q,s)=>{const r=await db.query('delete from notices where id=$1 returning t',[+q.params.id]);sweep();log(q.u.u,'deleted',r.rows[0]?r.rows[0].t:'#'+q.params.id);s.json({})}));
app.get('/log',auth('admin'),wrap(async(q,s)=>s.json((await db.query("select who,act,what,to_char(at at time zone 'Asia/Kolkata','DD Mon YYYY HH24:MI') as at from audit order by id desc limit 100")).rows)));
// staff management (admin only)
app.get('/staff',auth('admin'),wrap(async(q,s)=>s.json((await db.query('select username,role from staff order by username')).rows)));
app.post('/staff',auth('admin'),wrap(async(q,s)=>{const u=String(q.body.username||'').toLowerCase().trim(),p=String(q.body.password||'');
 if(!/^[a-z0-9._-]{3,30}$/.test(u)||p.length<8)return s.status(400).json({});
 await db.query("insert into staff values($1,$2,'staff') on conflict (username) do update set hash=excluded.hash",[u,await bcrypt.hash(p,12)]);s.json({})}));
app.delete('/staff/:u',auth('admin'),wrap(async(q,s)=>{if(q.params.u===q.u.u)return s.sendStatus(400);await db.query('delete from staff where username=$1',[q.params.u]);s.json({})}));
app.post('/me/password',auth(),wrap(async(q,s)=>{const p=String(q.body.password||'');if(p.length<8)return s.sendStatus(400);
 await db.query('update staff set hash=$1 where username=$2',[await bcrypt.hash(p,12),q.u.u]);s.json({})}));
app.listen(process.env.PORT||3000);
