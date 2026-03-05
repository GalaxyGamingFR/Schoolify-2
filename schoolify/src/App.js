import { useState, useMemo, useCallback, useRef } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, BarChart, Bar } from "recharts";

// ══════════════════════════════════════════════════════════════════
// ⚙️  BACKEND AGENT — Calc Engine
// ══════════════════════════════════════════════════════════════════
const calcWA = (a) => { const g=a.filter(x=>x.grade!==""&&x.weight>0); if(!g.length)return null; const tw=g.reduce((s,x)=>s+Number(x.weight),0); return tw?(g.reduce((s,x)=>s+(Number(x.grade)/100)*Number(x.weight),0)/tw)*100:null; };
const calcReq = (avg,gw,target,rw) => rw?Math.round(((target-(avg*gw)/100)/(rw/100))*10)/10:null;
const lg = p => p>=90?{l:"A+",c:"#4ade80"}:p>=85?{l:"A",c:"#4ade80"}:p>=80?{l:"A-",c:"#86efac"}:p>=77?{l:"B+",c:"#bef264"}:p>=73?{l:"B",c:"#bef264"}:p>=70?{l:"B-",c:"#fde68a"}:p>=67?{l:"C+",c:"#fbbf24"}:p>=63?{l:"C",c:"#fb923c"}:p>=60?{l:"C-",c:"#f87171"}:{l:"F",c:"#ef4444"};
const risk = p => p>=75?{label:"Low",color:"#4ade80",bg:"rgba(74,222,128,0.1)"}:p>=65?{label:"Medium",color:"#fbbf24",bg:"rgba(251,191,36,0.1)"}:{label:"High",color:"#f87171",bg:"rgba(248,113,113,0.1)"};
const gpa4 = p => p>=90?4.0:p>=85?3.9:p>=80?3.7:p>=77?3.3:p>=73?3.0:p>=70?2.7:p>=67?2.3:p>=63?2.0:p>=60?1.7:0.0;

// ══════════════════════════════════════════════════════════════════
// ⚙️  XP / Battlepass Engine
// ══════════════════════════════════════════════════════════════════
const LEVELS=[{lvl:1,min:0,max:100,title:"Freshman",c:"#64748b"},{lvl:2,min:100,max:250,title:"Sophomore",c:"#60a5fa"},{lvl:3,min:250,max:500,title:"Junior",c:"#34d399"},{lvl:4,min:500,max:900,title:"Senior",c:"#fbbf24"},{lvl:5,min:900,max:1400,title:"Honor Roll",c:"#f472b6"},{lvl:6,min:1400,max:2000,title:"Dean's List",c:"#a78bfa"},{lvl:7,min:2000,max:3000,title:"Valedictorian",c:"#fb923c"},{lvl:8,min:3000,max:9999,title:"Legend",c:"#ffd700"}];
const getLvl = xp => { const l=LEVELS.slice().reverse().find(l=>xp>=l.min)||LEVELS[0]; return{...l,progress:Math.min(((xp-l.min)/(l.max-l.min))*100,100)}; };
const ACHIEVEMENTS=[
  {id:"a1",icon:"✏️",title:"First Grade",desc:"Enter your first grade",xp:25,check:s=>s.gradesEntered>=1},
  {id:"a2",icon:"🧠",title:"Quiz Rookie",desc:"Complete first quiz",xp:50,check:s=>s.quizzes>=1},
  {id:"a3",icon:"⚡",title:"Flash Master",desc:"5 flashcard sets",xp:75,check:s=>s.flashcards>=5},
  {id:"a4",icon:"🔥",title:"On Fire",desc:"3-day streak",xp:60,check:s=>s.streak>=3},
  {id:"a5",icon:"💫",title:"Week Warrior",desc:"7-day streak",xp:150,check:s=>s.streak>=7},
  {id:"a6",icon:"💯",title:"Perfect Score",desc:"100% on a quiz",xp:100,check:s=>s.perfect>=1},
  {id:"a7",icon:"🌟",title:"A Student",desc:"Get an A in any course",xp:80,check:s=>s.aGrades>=1},
  {id:"a8",icon:"📊",title:"Grade Tracker",desc:"Enter 10+ grades",xp:50,check:s=>s.gradesEntered>=10},
  {id:"a9",icon:"🏆",title:"Overachiever",desc:"Reach Level 5",xp:200,check:s=>s.level>=5},
  {id:"a10",icon:"📚",title:"Studious",desc:"Use 3+ study tools",xp:75,check:s=>s.tools>=3},
];
const MOCK_LEADERBOARD=[
  {rank:1,name:"Jordan K.",school:"St. Mary's HS",xp:2840,lvl:7,streak:14,avatar:"J"},
  {rank:2,name:"Priya S.",school:"Westview Secondary",xp:2210,lvl:7,streak:9,avatar:"P"},
  {rank:3,name:"Alex C.",school:"Westview Secondary",xp:1520,lvl:6,streak:3,avatar:"A"},
  {rank:4,name:"Marcus T.",school:"Bayview Academy",xp:1380,lvl:5,streak:7,avatar:"M"},
  {rank:5,name:"Sophia L.",school:"North Shore CI",xp:1140,lvl:5,streak:5,avatar:"S"},
  {rank:6,name:"Devon R.",school:"Lakeview HS",xp:980,lvl:5,streak:2,avatar:"D"},
  {rank:7,name:"Nia W.",school:"Central Collegiate",xp:760,lvl:4,streak:8,avatar:"N"},
  {rank:8,name:"Tyler H.",school:"St. Mary's HS",xp:540,lvl:4,streak:1,avatar:"T"},
];

// ══════════════════════════════════════════════════════════════════
// 🌱 Seed Data
// ══════════════════════════════════════════════════════════════════
const PAL=["#818cf8","#f472b6","#34d399","#fb923c","#60a5fa","#a78bfa","#fbbf24","#f87171"];
const TC={Test:"#818cf8",Exam:"#f87171",Assignment:"#60a5fa",Lab:"#34d399",Quiz:"#fbbf24"};
const SEED={
  "2025-2026":{label:"2025–2026",current:true,courses:[
    {id:101,name:"Advanced Functions",code:"MHF4U",color:"#818cf8",assignments:[{id:1,name:"Unit 1 Test",weight:15,grade:88,type:"Test"},{id:2,name:"Assignment 1",weight:10,grade:92,type:"Assignment"},{id:3,name:"Midterm",weight:25,grade:79,type:"Exam"},{id:4,name:"Unit 2 Test",weight:15,grade:"",type:"Test"},{id:5,name:"Final Exam",weight:35,grade:"",type:"Exam"}]},
    {id:102,name:"English Literature",code:"ENG4U",color:"#f472b6",assignments:[{id:1,name:"Essay 1",weight:20,grade:84,type:"Assignment"},{id:2,name:"Presentation",weight:15,grade:90,type:"Assignment"},{id:3,name:"Midterm",weight:25,grade:76,type:"Exam"},{id:4,name:"Essay 2",weight:15,grade:"",type:"Assignment"},{id:5,name:"Final Exam",weight:25,grade:"",type:"Exam"}]},
    {id:103,name:"Chemistry",code:"SCH4U",color:"#34d399",assignments:[{id:1,name:"Lab Report 1",weight:10,grade:95,type:"Lab"},{id:2,name:"Unit Test 1",weight:20,grade:82,type:"Test"},{id:3,name:"Lab Report 2",weight:10,grade:88,type:"Lab"},{id:4,name:"Midterm",weight:25,grade:71,type:"Exam"},{id:5,name:"Final Exam",weight:35,grade:"",type:"Exam"}]},
    {id:104,name:"Calculus & Vectors",code:"MCV4U",color:"#fb923c",assignments:[{id:1,name:"Quiz 1",weight:10,grade:91,type:"Quiz"},{id:2,name:"Unit Test 1",weight:20,grade:85,type:"Test"},{id:3,name:"Midterm",weight:25,grade:80,type:"Exam"},{id:4,name:"Unit Test 2",weight:20,grade:"",type:"Test"},{id:5,name:"Final Exam",weight:25,grade:"",type:"Exam"}]},
  ]},
  "2024-2025":{label:"2024–2025",current:false,courses:[
    {id:201,name:"Grade 11 Math",code:"MCR3U",color:"#60a5fa",assignments:[{id:1,name:"Unit 1 Test",weight:20,grade:87,type:"Test"},{id:2,name:"Midterm",weight:30,grade:81,type:"Exam"},{id:3,name:"Assignment",weight:15,grade:90,type:"Assignment"},{id:4,name:"Final Exam",weight:35,grade:84,type:"Exam"}]},
    {id:202,name:"Grade 11 English",code:"ENG3U",color:"#a78bfa",assignments:[{id:1,name:"Essay 1",weight:25,grade:78,type:"Assignment"},{id:2,name:"Midterm",weight:25,grade:82,type:"Exam"},{id:3,name:"Essay 2",weight:25,grade:80,type:"Assignment"},{id:4,name:"Final Exam",weight:25,grade:75,type:"Exam"}]},
  ]},
};

const UNIS=[
  {id:"uoft",name:"U of Toronto",programs:[{name:"Computer Science",minAvg:95,comp:97,prereqs:["MHF4U","MCV4U"]},{name:"Life Sciences",minAvg:88,comp:92,prereqs:["SCH4U","MHF4U"]},{name:"Engineering",minAvg:93,comp:96,prereqs:["MHF4U","MCV4U","SCH4U"]}]},
  {id:"waterloo",name:"Waterloo",programs:[{name:"Computer Science",minAvg:92,comp:95,prereqs:["MHF4U","MCV4U"]},{name:"Software Eng",minAvg:93,comp:96,prereqs:["MHF4U","MCV4U"]},{name:"Mathematics",minAvg:88,comp:91,prereqs:["MHF4U","MCV4U"]}]},
  {id:"mcmaster",name:"McMaster",programs:[{name:"Health Sciences",minAvg:92,comp:94,prereqs:["SCH4U","MHF4U","ENG4U"]},{name:"Engineering",minAvg:85,comp:89,prereqs:["MHF4U","MCV4U","SCH4U"]}]},
  {id:"queens",name:"Queen's",programs:[{name:"Commerce",minAvg:87,comp:90,prereqs:["MHF4U","ENG4U"]},{name:"Engineering",minAvg:85,comp:88,prereqs:["MHF4U","MCV4U"]}]},
  {id:"western",name:"Western",programs:[{name:"Ivey AEO",minAvg:88,comp:91,prereqs:["MHF4U","ENG4U"]},{name:"Medical Sciences",minAvg:88,comp:91,prereqs:["SCH4U","MHF4U"]}]},
];

const SCHOLARSHIPS=[
  {name:"TD Scholarship for Community Leadership",amount:"$70,000",deadline:"2025-11-30",gpa:"80%+",type:"Leadership",url:"#"},
  {name:"Loran Award",amount:"$100,000",deadline:"2025-11-01",gpa:"85%+",type:"Leadership",url:"#"},
  {name:"Schulich Leader Scholarship",amount:"$100,000",deadline:"2026-01-15",gpa:"Top of class",type:"STEM",url:"#"},
  {name:"Terry Fox Humanitarian Award",amount:"$28,000",deadline:"2026-02-01",gpa:"80%+",type:"Humanitarian",url:"#"},
  {name:"RBC Future Launch",amount:"$10,000",deadline:"2026-03-01",gpa:"None",type:"Community",url:"#"},
  {name:"Canada Student Grant",amount:"$4,200/yr",deadline:"Rolling",gpa:"None",type:"Government",url:"#"},
  {name:"OSAP",amount:"Varies",deadline:"Rolling",gpa:"None",type:"Government",url:"#"},
  {name:"Governor General's Academic Medal",amount:"Prestige",deadline:"School nominated",gpa:"Top in school",type:"Academic",url:"#"},
];

const COMPETITIONS=[
  {name:"Canadian Computing Competition",subject:"Computer Science",level:"National",deadline:"Feb 2026",prize:"Awards + recognition",url:"#"},
  {name:"Euclid Mathematics Contest",subject:"Mathematics",level:"National",deadline:"Apr 2026",prize:"Awards + Waterloo admission boost",url:"#"},
  {name:"Science Olympics",subject:"Science",level:"Regional/National",deadline:"Jan 2026",prize:"Medals + scholarships",url:"#"},
  {name:"Canada-Wide Science Fair",subject:"All Sciences",level:"National",deadline:"Mar 2026",prize:"$100,000+ total prizes",url:"#"},
  {name:"Debate Canada Nationals",subject:"English/Debate",level:"National",deadline:"Feb 2026",prize:"Trophies + recognition",url:"#"},
  {name:"Math Kangaroo",subject:"Mathematics",level:"International",deadline:"Mar 2026",prize:"Medals",url:"#"},
  {name:"Hackathon — UofT Blueprint",subject:"Technology",level:"University-run",deadline:"Jan 2026",prize:"$5,000+",url:"#"},
  {name:"MIT THINK Scholars",subject:"Research",level:"International",deadline:"Dec 2025",prize:"$1,000 + mentorship",url:"#"},
];

const CAREERS=[
  {field:"Medicine & Health",icon:"🏥",avgSalary:"$120k-$300k",topPaths:["Family Doctor","Surgeon","Pharmacist","Physiotherapist"],reqCourses:["SCH4U","SBI4U","MHF4U","ENG4U"],unis:["McMaster","U of T","Western"],timeframe:"8-12 yrs"},
  {field:"Engineering",icon:"⚙️",avgSalary:"$80k-$150k",topPaths:["Software Engineer","Civil Eng","Electrical Eng","Mechanical Eng"],reqCourses:["MHF4U","MCV4U","SPH4U","SCH4U"],unis:["Waterloo","U of T","McMaster"],timeframe:"4 yrs"},
  {field:"Computer Science",icon:"💻",avgSalary:"$90k-$200k+",topPaths:["Software Developer","Data Scientist","ML Engineer","Product Manager"],reqCourses:["MHF4U","MCV4U","ICS4U"],unis:["Waterloo","U of T","UBC"],timeframe:"4 yrs"},
  {field:"Business & Commerce",icon:"📈",avgSalary:"$70k-$200k+",topPaths:["Finance","Marketing","Consulting","Entrepreneurship"],reqCourses:["MHF4U","ENG4U","BAF3M"],unis:["Western Ivey","Queen's","Schulich"],timeframe:"4 yrs"},
  {field:"Law",icon:"⚖️",avgSalary:"$90k-$300k",topPaths:["Corporate Lawyer","Criminal Defence","Crown Attorney","Notary"],reqCourses:["ENG4U","HSB4U"],unis:["U of T","Osgoode","Queens"],timeframe:"7 yrs"},
  {field:"Education",icon:"🎓",avgSalary:"$55k-$95k",topPaths:["Teacher","Principal","Curriculum Designer","Professor"],reqCourses:["ENG4U"],unis:["OISE","Queens","Western"],timeframe:"5-6 yrs"},
];

// ══════════════════════════════════════════════════════════════════
// 🎨 Shared UI Primitives
// ══════════════════════════════════════════════════════════════════
const C = ({children,p=20,style={}}) => <div style={{background:"#0c1420",border:"1px solid #0f1e30",borderRadius:14,padding:p,...style}}>{children}</div>;
const Label = ({children}) => <div style={{fontSize:10,color:"#475569",textTransform:"uppercase",letterSpacing:.8,marginBottom:6}}>{children}</div>;
const Inp = ({style={},...p}) => <input style={{background:"#080c14",border:"1px solid #1e2d45",borderRadius:8,padding:"8px 12px",color:"#e2e8f0",fontSize:13,fontFamily:"inherit",outline:"none",width:"100%",...style}} {...p}/>;
const Sel = ({children,style={},...p}) => <select style={{background:"#080c14",border:"1px solid #1e2d45",borderRadius:8,padding:"8px 12px",color:"#e2e8f0",fontSize:13,fontFamily:"inherit",outline:"none",width:"100%",...style}} {...p}>{children}</select>;
const Btn = ({children,v="primary",style={},...p}) => <button style={{padding:"9px 18px",borderRadius:9,border:"none",cursor:"pointer",fontSize:13,fontFamily:"inherit",fontWeight:600,transition:"all .15s",
  ...(v==="primary"?{background:"linear-gradient(135deg,#2563eb,#4f46e5)",color:"#fff"}:
     v==="ghost"?{background:"transparent",border:"1px solid #1e2d45",color:"#64748b"}:
     v==="soft"?{background:"rgba(99,102,241,0.1)",border:"1px solid rgba(99,102,241,0.2)",color:"#a78bfa"}:
     {background:"rgba(248,113,113,0.1)",border:"1px solid rgba(248,113,113,0.2)",color:"#f87171"}),
  ...style}} {...p}>{children}</button>;
const Tag = ({children,color="#60a5fa",size=10}) => <span style={{fontSize:size,padding:"2px 8px",borderRadius:99,background:color+"20",color,fontWeight:600}}>{children}</span>;

// Icon helper
const Ic = ({n,s=15}) => ({
  dash:   <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>,
  opt:    <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>,
  gpa:    <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="M7 16l4-4 4 4 4-6"/></svg>,
  uni:    <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M3 21h18M9 8h1m4 0h1M9 12h1m4 0h1M5 21V7l7-4 7 4v14"/></svg>,
  ai:     <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20A10 10 0 0012 2z"/><path d="M12 8v4l3 3"/></svg>,
  fire:   <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M12 2s-4 4-4 9a4 4 0 008 0c0-2-.8-4-1.5-5 0 2-1.5 3-2.5 3s-2-1-2-2c0-2 2-5 2-5z"/></svg>,
  trophy: <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M6 9H4a2 2 0 01-2-2V5h4M18 9h2a2 2 0 002-2V5h-4M12 17v4M8 21h8M6 9a6 6 0 0012 0V3H6v6z"/></svg>,
  user:   <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>,
  logout: <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/></svg>,
  plus:   <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>,
  trash:  <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg>,
  check:  <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>,
  x:      <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
  alert:  <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  medal:  <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><circle cx="12" cy="15" r="6"/><path d="M8.5 8.5L5 3h14l-3.5 5.5"/></svg>,
  brief:  <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v2"/></svg>,
  compass:<svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/></svg>,
  school: <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5"/></svg>,
  redo:   <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>,
  upload: <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0018 9h-1.26A8 8 0 103 16.3"/></svg>,
  cal:    <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>,
  save:   <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>,
  lock:   <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>,
  pencil: <svg width={s} height={s} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>,
}[n]||null);

// ══════════════════════════════════════════════════════════════════
// 🔐 Auth Screen
// ══════════════════════════════════════════════════════════════════
const AuthScreen = ({onAuth}) => {
  const [mode,setMode]=useState("login");
  const [form,setForm]=useState({email:"",password:"",firstName:"",lastName:"",role:"student",school:"",country:"Canada",province:"Ontario"});
  const [err,setErr]=useState("");
  const [loading,setLoading]=useState(false);
  const set=k=>e=>setForm(p=>({...p,[k]:e.target.value}));
  const submit=async()=>{
    setErr("");setLoading(true);
    await new Promise(r=>setTimeout(r,600));
    if(!form.email||!form.password){setErr("Email and password required");setLoading(false);return;}
    onAuth("demo_token",{firstName:form.firstName||"Alex",lastName:form.lastName||"Chen",email:form.email,role:form.role,school:form.school||"Westview Secondary",country:form.country,province:form.province});
    setLoading(false);
  };
  return(
    <div style={{minHeight:"100vh",background:"#080c14",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'Sora',sans-serif"}}>
      <div style={{width:440,padding:32}}>
        <div style={{textAlign:"center",marginBottom:32}}>
          <div style={{width:52,height:52,background:"linear-gradient(135deg,#3b82f6,#6366f1)",borderRadius:14,display:"flex",alignItems:"center",justifyContent:"center",fontWeight:900,fontSize:24,margin:"0 auto 12px"}}>S</div>
          <div style={{fontSize:28,fontWeight:900,background:"linear-gradient(135deg,#fff,#94a3b8)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent",letterSpacing:"-1px"}}>Schoolify</div>
          <div style={{fontSize:13,color:"#475569",marginTop:4}}>Your academic command centre</div>
        </div>
        <C p={28}>
          <div style={{display:"flex",gap:4,marginBottom:22,background:"#080c14",borderRadius:10,padding:3}}>
            {["login","signup"].map(m=><button key={m} onClick={()=>setMode(m)} style={{flex:1,padding:"8px",borderRadius:8,border:"none",cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600,background:mode===m?"#0f1e30":"transparent",color:mode===m?"#e2e8f0":"#475569",transition:"all .15s",textTransform:"capitalize"}}>{m==="login"?"Sign In":"Create Account"}</button>)}
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:10}}>
            {mode==="signup"&&<>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}><Inp placeholder="First name" value={form.firstName} onChange={set("firstName")}/><Inp placeholder="Last name" value={form.lastName} onChange={set("lastName")}/></div>
              <Inp placeholder="School name" value={form.school} onChange={set("school")}/>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
                <Sel value={form.country} onChange={set("country")}><option>Canada</option><option>USA</option><option>UK</option><option>Australia</option><option>Other</option></Sel>
                <Inp placeholder="Province / State" value={form.province} onChange={set("province")}/>
              </div>
              <Sel value={form.role} onChange={set("role")}><option value="student">Student</option><option value="parent">Parent</option></Sel>
            </>}
            <Inp type="email" placeholder="Email address" value={form.email} onChange={set("email")}/>
            <Inp type="password" placeholder="Password" value={form.password} onChange={set("password")}/>
            {err&&<div style={{fontSize:12,color:"#f87171",padding:"8px 12px",background:"rgba(248,113,113,0.08)",borderRadius:8}}>{err}</div>}
            <Btn onClick={submit} style={{width:"100%",padding:12,marginTop:2}} disabled={loading}>{loading?"Loading...":(mode==="login"?"Sign In":"Create Account")}</Btn>
          </div>
        </C>
        <div style={{textAlign:"center",marginTop:14}}>
          <button onClick={()=>onAuth("demo",{firstName:"Alex",lastName:"Chen",email:"alex@demo.com",role:"student",school:"Westview Secondary",province:"Ontario",country:"Canada"})} style={{background:"transparent",border:"none",color:"#334155",fontSize:12,cursor:"pointer",fontFamily:"inherit",textDecoration:"underline"}}>Try demo →</button>
        </div>
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════
// 📅 Add Year Modal
// ══════════════════════════════════════════════════════════════════
const AddYearModal=({existing,onAdd,onClose})=>{
  const [start,setStart]=useState(new Date().getFullYear()-1);
  const key=`${start}-${start+1}`;const exists=existing.includes(key);
  return(
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.75)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:999}}>
      <C p={28} style={{width:340}}>
        <div style={{fontSize:15,fontWeight:700,marginBottom:18}}>Add Academic Year</div>
        <Label>Start Year</Label>
        <Sel value={start} onChange={e=>setStart(Number(e.target.value))} style={{marginBottom:16}}>
          {Array.from({length:10},(_,i)=>new Date().getFullYear()-i).map(y=><option key={y} value={y}>{y}</option>)}
        </Sel>
        <div style={{padding:"10px 14px",background:"#080c14",borderRadius:9,marginBottom:16,display:"flex",justifyContent:"space-between"}}>
          <span style={{fontSize:12,color:"#475569"}}>Year label</span>
          <span style={{fontFamily:"'DM Mono',monospace",fontWeight:700,color:exists?"#f87171":"#60a5fa"}}>{start}–{start+1}</span>
        </div>
        {exists&&<div style={{fontSize:11,color:"#f87171",marginBottom:10}}>Already exists.</div>}
        <div style={{display:"flex",gap:8}}>
          <Btn v="ghost" onClick={onClose} style={{flex:1}}>Cancel</Btn>
          <Btn onClick={()=>!exists&&onAdd(key,`${start}–${start+1}`)} style={{flex:1,opacity:exists?.4:1}}>Add Year</Btn>
        </div>
      </C>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════
// 📊 Dashboard Tab
// ══════════════════════════════════════════════════════════════════
const DashboardTab=({enrichedYear,years,activeYear,ys,profile,setTab,setSelectedId})=>{
  const isParent=profile?.role==="parent";
  return(
    <div>
      <div style={{marginBottom:20}}>
        <h2 style={{fontSize:20,fontWeight:800,letterSpacing:"-0.5px"}}>Hi {profile?.firstName} 👋</h2>
        <p style={{color:"#475569",fontSize:13,marginTop:3}}>{years[activeYear]?.label} · {profile?.school||"No school set"}</p>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:20}}>
        {[{l:"GPA",v:ys.gpa||"—",s:"4.0 scale",c:"#60a5fa"},{l:"Top 6 Avg",v:ys.top6?ys.top6+"%":"—",s:"Ontario",c:"#a78bfa"},{l:"Courses",v:enrichedYear.length,s:"This year",c:"#34d399"},{l:"Pending",v:enrichedYear.reduce((s,c)=>s+c.assignments.filter(a=>a.grade==="").length,0),s:"Ungraded",c:"#fbbf24"}].map((s,i)=>(
          <C key={i} p={16}><Label>{s.l}</Label><div style={{fontSize:28,fontWeight:900,color:s.c,fontFamily:"'DM Mono',monospace",letterSpacing:"-1px"}}>{s.v}</div><div style={{fontSize:10,color:"#334155",marginTop:3}}>{s.s}</div></C>
        ))}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))",gap:12}}>
        {enrichedYear.map(c=>{const g=c.avg!=null?lg(c.avg):null;const r=c.avg!=null?risk(c.avg):null;const pct=(c.gw/c.tw)*100||0;return(
          <div key={c.id} onClick={()=>{setSelectedId(c.id);setTab("optimizer");}} style={{background:"#0c1420",border:"1px solid #0f1e30",borderRadius:13,padding:16,cursor:"pointer",transition:"all .18s",position:"relative",overflow:"hidden"}}
            onMouseEnter={e=>e.currentTarget.style.transform="translateY(-2px)"} onMouseLeave={e=>e.currentTarget.style.transform=""}>
            <div style={{position:"absolute",top:0,left:0,right:0,height:3,background:c.color}}/>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
              <div><div style={{fontWeight:700,fontSize:13}}>{c.name}</div><div style={{fontSize:10,color:"#475569",fontFamily:"'DM Mono',monospace"}}>{c.code}</div></div>
              {g?<div style={{textAlign:"right"}}><div style={{fontSize:20,fontWeight:800,color:g.c,fontFamily:"'DM Mono',monospace",lineHeight:1}}>{g.l}</div><div style={{fontSize:11,color:"#94a3b8",fontFamily:"'DM Mono',monospace"}}>{c.avg?.toFixed(1)}%</div></div>:<div style={{fontSize:10,color:"#334155"}}>No grades</div>}
            </div>
            <div style={{marginBottom:8}}><div style={{height:3,background:"#0f1e30",borderRadius:99}}><div style={{height:"100%",background:c.color,borderRadius:99,width:pct+"%",transition:"width .5s"}}/></div><div style={{fontSize:9,color:"#334155",marginTop:3}}>{Math.round(pct)}% graded</div></div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              {r&&<Tag color={r.color} size={9}>{r.label} Risk</Tag>}
              {c.required!=null&&c.rw>0&&<span style={{fontSize:9,color:"#475569"}}>Need <b style={{color:c.required>100?"#f87171":"#60a5fa"}}>{c.required>100?"100%+":c.required+"%"}</b></span>}
            </div>
          </div>
        )})}
      </div>
      {isParent&&(
        <div style={{marginTop:20}}>
          <div style={{fontSize:13,fontWeight:700,marginBottom:12,color:"#c084fc"}}>👨‍👩‍👧 Parent Overview</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))",gap:10}}>
            {enrichedYear.filter(c=>c.avg!=null).map(c=>{const r=risk(c.avg);return(
              <C key={c.id} p={14} style={{borderLeft:`3px solid ${c.color}`}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <div><div style={{fontSize:12,fontWeight:600}}>{c.name}</div><div style={{fontSize:10,color:"#475569"}}>{c.assignments.filter(a=>a.grade!=="").length}/{c.assignments.length} graded</div></div>
                  <div style={{display:"flex",gap:8,alignItems:"center"}}>
                    <span style={{fontSize:16,fontWeight:800,color:lg(c.avg).c,fontFamily:"'DM Mono',monospace"}}>{c.avg?.toFixed(1)}%</span>
                    <Tag color={r.color} size={9}>{r.label}</Tag>
                  </div>
                </div>
              </C>
            )})};
          </div>
        </div>
      )}
    </div>  
  )};

// ══════════════════════════════════════════════════════════════════
// 🎯 Optimizer + What-If (merged)
// ══════════════════════════════════════════════════════════════════
const OptimizerTab=({years,activeYear,enrichedYear,targetGrade,setTargetGrade,selectedId,setSelectedId,updateGrade,addAssignment,delAssignment,addCourse,findYK})=>{
  const [subTab,setSubTab]=useState("optimizer");
  const [showAddC,setShowAddC]=useState(false);
  const [showAddA,setShowAddA]=useState(false);
  const [newC,setNewC]=useState({name:"",code:""});
  const [newA,setNewA]=useState({name:"",weight:"",grade:"",type:"Assignment"});
  const [wiGrades,setWiGrades]=useState({});
  const [wiScen,setWiScen]=useState("custom");

  const allCourses=useMemo(()=>Object.values(years).flatMap(y=>y.courses),[years]);
  const course=useMemo(()=>allCourses.find(c=>c.id===selectedId),[allCourses,selectedId]);
  const ec=useMemo(()=>enrichedYear.find(c=>c.id===selectedId)||null,[enrichedYear,selectedId]);
  const yk=findYK(selectedId);
  const isCurrent=years[yk]?.current;

  const trendData=useMemo(()=>{
    if(!course)return[];
    const g=course.assignments.filter(a=>a.grade!=="");
    let r=0,tw=0;
    return g.map(a=>{r+=(Number(a.grade)/100)*Number(a.weight);tw+=Number(a.weight);return{name:a.name.slice(0,10),avg:Math.round((r/tw)*1000)/10,raw:Number(a.grade)};});
  },[course]);

  const wiResult=useMemo(()=>{
    if(!course)return null;
    const sim=wiScen==="optimistic"?course.assignments.map(a=>({...a,grade:a.grade!==""?a.grade:95}))
      :wiScen==="realistic"?course.assignments.map(a=>({...a,grade:a.grade!==""?a.grade:78}))
      :wiScen==="worst"?course.assignments.map(a=>({...a,grade:a.grade!==""?a.grade:55}))
      :course.assignments.map(a=>({...a,grade:wiGrades[a.id]!==undefined?wiGrades[a.id]:a.grade}));
    return{avg:calcWA(sim),sim};
  },[course,wiGrades,wiScen]);

  const inp={background:"#080c14",border:"1px solid #1e2d45",borderRadius:8,padding:"7px 10px",color:"#e2e8f0",fontSize:12,fontFamily:"inherit",outline:"none"};

  return(
    <div style={{display:"grid",gridTemplateColumns:"220px 1fr",gap:16,height:"100%"}}>
      {/* Sidebar */}
      <div style={{display:"flex",flexDirection:"column",gap:6}}>
        <Label>Year Courses</Label>
        {enrichedYear.map(c=>(
          <div key={c.id} onClick={()=>setSelectedId(c.id)} style={{background:selectedId===c.id?"#0f1e30":"#0c1420",border:`1px solid ${selectedId===c.id?c.color+"50":"#0f1e30"}`,borderRadius:9,padding:"9px 12px",cursor:"pointer",display:"flex",justifyContent:"space-between",alignItems:"center",transition:"all .15s"}}>
            <div><div style={{fontSize:12,fontWeight:600,color:selectedId===c.id?"#e2e8f0":"#94a3b8"}}>{c.name}</div><div style={{fontSize:9,color:"#475569",fontFamily:"'DM Mono',monospace"}}>{c.code}</div></div>
            {c.avg!=null&&<span style={{fontSize:12,fontWeight:700,color:lg(c.avg).c,fontFamily:"'DM Mono',monospace"}}>{c.avg?.toFixed(0)}%</span>}
          </div>
        ))}
        {isCurrent&&<button onClick={()=>setShowAddC(!showAddC)} style={{background:"transparent",border:"1px dashed #1e2d45",borderRadius:9,padding:"7px",color:"#475569",fontSize:11,fontFamily:"inherit",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",gap:5}}><Ic n="plus" s={11}/> Add Course</button>}
        {showAddC&&<div style={{background:"#0c1420",border:"1px solid #0f1e30",borderRadius:9,padding:10,display:"flex",flexDirection:"column",gap:6}}>
          <input value={newC.name} onChange={e=>setNewC(p=>({...p,name:e.target.value}))} placeholder="Course name" style={inp}/>
          <input value={newC.code} onChange={e=>setNewC(p=>({...p,code:e.target.value}))} placeholder="Code e.g. MHF4U" style={inp}/>
          <Btn onClick={()=>{addCourse(newC);setNewC({name:"",code:""});setShowAddC(false);}} style={{padding:"6px"}}>Add</Btn>
        </div>}
        <div style={{marginTop:8,background:"#0c1420",border:"1px solid #0f1e30",borderRadius:10,padding:12}}>
          <Label>Target Grade</Label>
          <div style={{display:"flex",alignItems:"center",gap:8}}><input type="range" min={50} max={100} value={targetGrade} onChange={e=>setTargetGrade(Number(e.target.value))} style={{flex:1,accentColor:"#3b82f6"}}/><span style={{fontFamily:"'DM Mono',monospace",fontSize:13,fontWeight:700,color:"#60a5fa",minWidth:36}}>{targetGrade}%</span></div>
        </div>
      </div>

      {/* Main */}
      {ec&&course?(
        <div>
          {/* Course header */}
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:14}}>
            <div>
              <h2 style={{fontSize:17,fontWeight:800}}>{course.name}</h2>
              <div style={{fontSize:11,color:"#475569",fontFamily:"'DM Mono',monospace",marginTop:2}}>{course.code} · {years[yk]?.label}{!isCurrent&&<span style={{color:"#fbbf24",marginLeft:6}}>· Read Only</span>}</div>
            </div>
            {ec.avg!=null&&(
              <div style={{display:"flex",gap:14}}>
                {[{l:"Avg",v:ec.avg.toFixed(1)+"%",c:lg(ec.avg).c},{l:"Grade",v:lg(ec.avg).l,c:lg(ec.avg).c},{l:"GPA",v:gpa4(ec.avg).toFixed(1),c:"#60a5fa"}].map((s,i)=>(
                  <div key={i} style={{textAlign:"right"}}><div style={{fontSize:9,color:"#475569"}}>{s.l}</div><div style={{fontSize:22,fontWeight:900,color:s.c,fontFamily:"'DM Mono',monospace",lineHeight:1.1}}>{s.v}</div></div>
                ))}
              </div>
            )}
          </div>

          {/* Sub-tabs */}
          <div style={{display:"flex",gap:4,marginBottom:14,background:"#080c14",borderRadius:9,padding:3,alignSelf:"start",width:"fit-content"}}>
            {[{id:"optimizer",label:"📊 Optimizer"},{id:"whatif",label:"🔮 What-If"}].map(t=>(
              <button key={t.id} onClick={()=>setSubTab(t.id)} style={{padding:"6px 14px",borderRadius:7,border:"none",cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600,background:subTab===t.id?"#0f1e30":"transparent",color:subTab===t.id?"#e2e8f0":"#475569",transition:"all .15s"}}>{t.label}</button>
            ))}
          </div>

          {/* OPTIMIZER sub-tab */}
          {subTab==="optimizer"&&(
            <div>
              {ec.required!=null&&ec.rw>0&&isCurrent&&(
                <div style={{padding:"11px 16px",borderRadius:10,marginBottom:12,background:ec.required>100?"rgba(248,113,113,0.07)":"rgba(59,130,246,0.07)",border:`1px solid ${ec.required>100?"#f8717125":"#3b82f625"}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <span style={{fontSize:12,color:"#64748b"}}>To reach <b style={{color:"#94a3b8"}}>{targetGrade}%</b> on remaining <b style={{color:"#94a3b8"}}>{ec.rw}%</b>:</span>
                  <span style={{fontSize:24,fontWeight:900,fontFamily:"'DM Mono',monospace",color:ec.required>100?"#f87171":ec.required<=0?"#4ade80":"#60a5fa"}}>{ec.required>100?"Not achievable":ec.required<=0?"Done! 🎉":ec.required+"%"}</span>
                </div>
              )}
              <C p={0} style={{overflow:"hidden",marginBottom:12}}>
                <div style={{padding:"11px 16px",borderBottom:"1px solid #0f1e30",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <span style={{fontSize:13,fontWeight:600}}>Assessments</span>
                  {isCurrent&&<button onClick={()=>setShowAddA(!showAddA)} style={{background:"rgba(59,130,246,0.1)",border:"1px solid rgba(59,130,246,0.2)",borderRadius:7,padding:"4px 11px",color:"#60a5fa",fontSize:12,fontFamily:"inherit",cursor:"pointer",display:"flex",alignItems:"center",gap:5}}><Ic n="plus" s={11}/> Add</button>}
                </div>
                {showAddA&&<div style={{padding:"10px 16px",borderBottom:"1px solid #0f1e30",display:"flex",gap:6,flexWrap:"wrap",background:"#080c14"}}>
                  <input value={newA.name} onChange={e=>setNewA(p=>({...p,name:e.target.value}))} placeholder="Name" style={{...inp,flex:2,minWidth:100}}/>
                  <input value={newA.weight} onChange={e=>setNewA(p=>({...p,weight:e.target.value}))} placeholder="Wt%" type="number" style={{...inp,width:70}}/>
                  <input value={newA.grade} onChange={e=>setNewA(p=>({...p,grade:e.target.value}))} placeholder="Grade%" type="number" style={{...inp,width:70}}/>
                  <select value={newA.type} onChange={e=>setNewA(p=>({...p,type:e.target.value}))} style={inp}>{["Test","Exam","Assignment","Lab","Quiz"].map(t=><option key={t}>{t}</option>)}</select>
                  <Btn onClick={()=>{addAssignment(newA);setNewA({name:"",weight:"",grade:"",type:"Assignment"});setShowAddA(false);}} style={{padding:"6px 12px"}}>Save</Btn>
                </div>}
                <div style={{padding:"0 16px 6px"}}>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 60px 80px 100px 26px",gap:6,padding:"7px 0",borderBottom:"1px solid #0a1525",fontSize:9,color:"#334155",textTransform:"uppercase",letterSpacing:.5}}>
                    <span>Assessment</span><span style={{textAlign:"center"}}>Wt</span><span style={{textAlign:"center"}}>Grade</span><span style={{textAlign:"center"}}>Bar</span><span/>
                  </div>
                  {course.assignments.map(a=>(
                    <div key={a.id} style={{display:"grid",gridTemplateColumns:"1fr 60px 80px 100px 26px",gap:6,padding:"7px 0",borderBottom:"1px solid #0a1525",alignItems:"center"}}>
                      <div style={{display:"flex",alignItems:"center",gap:6}}><span style={{fontSize:9,padding:"1px 6px",borderRadius:99,background:(TC[a.type]||"#60a5fa")+"20",color:TC[a.type]||"#60a5fa",fontWeight:600}}>{a.type}</span><span style={{fontSize:12}}>{a.name}</span></div>
                      <div style={{textAlign:"center",fontSize:11,color:"#64748b",fontFamily:"'DM Mono',monospace"}}>{a.weight}%</div>
                      <div style={{textAlign:"center"}}>
                        {isCurrent?<input type="number" min={0} max={100} value={a.grade} onChange={e=>updateGrade(selectedId,yk,a.id,e.target.value)} placeholder="—" style={{width:58,background:"#080c14",border:"1px solid #1e2d45",borderRadius:6,padding:"4px 7px",color:a.grade!==""?lg(Number(a.grade)).c:"#334155",fontSize:12,textAlign:"center",fontFamily:"'DM Mono',monospace",outline:"none"}}/>
                        :<span style={{fontSize:12,fontFamily:"'DM Mono',monospace",color:a.grade!==""?lg(Number(a.grade)).c:"#334155"}}>{a.grade!==""?a.grade+"%":"—"}</span>}
                      </div>
                      <div>{a.grade!==""?<div style={{height:3,background:"#0f1e30",borderRadius:99}}><div style={{height:"100%",borderRadius:99,width:Math.min(Number(a.grade),100)+"%",background:Number(a.grade)>=85?"#4ade80":Number(a.grade)>=70?"#fbbf24":"#f87171"}}/></div>:<span style={{fontSize:9,color:"#1e2d45"}}>Pending</span>}</div>
                      {isCurrent&&<button onClick={()=>delAssignment(a.id)} style={{background:"none",border:"none",color:"#1e2d45",padding:2,cursor:"pointer",display:"flex"}}><Ic n="trash" s={11}/></button>}
                    </div>
                  ))}
                </div>
              </C>
              {trendData.length>1&&<C p={16}><div style={{fontSize:12,fontWeight:600,marginBottom:10}}>Grade Trend</div>
                <ResponsiveContainer width="100%" height={140}><LineChart data={trendData}><CartesianGrid strokeDasharray="3 3" stroke="#0a1525"/><XAxis dataKey="name" tick={{fontSize:9,fill:"#475569"}} axisLine={false} tickLine={false}/><YAxis domain={[50,100]} tick={{fontSize:9,fill:"#475569"}} axisLine={false} tickLine={false}/><Tooltip contentStyle={{background:"#0c1420",border:"1px solid #1e2d45",borderRadius:8,fontSize:11}}/><Line type="monotone" dataKey="avg" stroke="#3b82f6" strokeWidth={2} dot={{fill:"#3b82f6",r:3}} name="Running Avg"/><Line type="monotone" dataKey="raw" stroke="#6366f1" strokeWidth={1.5} strokeDasharray="4 4" dot={false} name="Raw"/></LineChart></ResponsiveContainer>
              </C>}
            </div>
          )}

          {/* WHAT-IF sub-tab */}
          {subTab==="whatif"&&wiResult&&(
            <div>
              <div style={{padding:"5px 0 12px",fontSize:11,color:"#fbbf24"}}>⚠️ Sandbox only — never touches your real grades.</div>
              <div style={{display:"flex",gap:6,marginBottom:14,flexWrap:"wrap"}}>
                {[{id:"custom",label:"✏️ Custom",c:"#60a5fa"},{id:"optimistic",label:"🚀 Optimistic (95%)",c:"#4ade80"},{id:"realistic",label:"📊 Realistic (78%)",c:"#fbbf24"},{id:"worst",label:"⚠️ Worst (55%)",c:"#f87171"}].map(s=>(
                  <button key={s.id} onClick={()=>setWiScen(s.id)} style={{padding:"5px 12px",borderRadius:99,border:`1px solid ${wiScen===s.id?s.c+"60":"#0f1e30"}`,background:wiScen===s.id?s.c+"15":"transparent",color:wiScen===s.id?s.c:"#64748b",fontSize:11,fontFamily:"inherit",cursor:"pointer"}}>{s.label}</button>
                ))}
              </div>
              <div style={{display:"flex",gap:16,alignItems:"center",padding:"12px 16px",background:"#080c14",borderRadius:10,marginBottom:12}}>
                <div><div style={{fontSize:9,color:"#475569"}}>Real</div><div style={{fontSize:26,fontWeight:900,fontFamily:"'DM Mono',monospace",color:ec?.avg!=null?lg(ec.avg).c:"#334155"}}>{ec?.avg?.toFixed(1)??"—"}%</div></div>
                <div style={{fontSize:18,color:"#1e2d45"}}>→</div>
                <div><div style={{fontSize:9,color:"#475569"}}>Simulated</div><div style={{fontSize:26,fontWeight:900,fontFamily:"'DM Mono',monospace",color:wiResult.avg!=null?lg(wiResult.avg).c:"#334155"}}>{wiResult.avg?.toFixed(1)??"—"}%</div></div>
                {wiResult.avg!=null&&ec?.avg!=null&&<><div style={{fontSize:18,color:"#1e2d45"}}>=</div><div><div style={{fontSize:9,color:"#475569"}}>Δ</div><div style={{fontSize:26,fontWeight:900,fontFamily:"'DM Mono',monospace",color:wiResult.avg>ec.avg?"#4ade80":"#f87171"}}>{wiResult.avg>ec.avg?"+":""}{(wiResult.avg-ec.avg).toFixed(1)}%</div></div></>}
                <div style={{marginLeft:"auto",padding:"8px 12px",background:"rgba(99,102,241,0.1)",borderRadius:9}}><div style={{fontSize:9,color:"#475569"}}>Grade</div><div style={{fontSize:20,fontWeight:900,color:wiResult.avg!=null?lg(wiResult.avg).c:"#334155",fontFamily:"'DM Mono',monospace"}}>{wiResult.avg!=null?lg(wiResult.avg).l:"—"}</div></div>
              </div>
              <div style={{display:"flex",flexDirection:"column",gap:7}}>
                {course.assignments.map(a=>{
                  const sim=wiResult.sim.find(x=>x.id===a.id);const isU=a.grade==="";
                  if(wiScen!=="custom"&&!isU)return null;
                  return(
                    <div key={a.id} style={{display:"grid",gridTemplateColumns:"1fr 90px 180px",gap:12,alignItems:"center",padding:"9px 12px",background:"#080c14",borderRadius:8,opacity:!isU&&wiScen==="custom"?.4:1}}>
                      <div><div style={{display:"flex",gap:5,alignItems:"center"}}><span style={{fontSize:9,padding:"1px 5px",borderRadius:99,background:(TC[a.type]||"#60a5fa")+"20",color:TC[a.type]||"#60a5fa"}}>{a.type}</span><span style={{fontSize:12}}>{a.name}</span></div><div style={{fontSize:9,color:"#475569",marginTop:1}}>{a.weight}% weight</div></div>
                      <div style={{textAlign:"center",fontSize:11,fontFamily:"'DM Mono',monospace"}}>{isU?<span style={{color:"#334155"}}>ungraded</span>:<span style={{color:lg(Number(a.grade)).c}}>{a.grade}% real</span>}</div>
                      <div style={{display:"flex",alignItems:"center",gap:8}}><input type="range" min={0} max={100} disabled={!isU&&wiScen==="custom"} value={sim?.grade!==""?sim?.grade:75} onChange={e=>{if(wiScen==="custom")setWiGrades(p=>({...p,[a.id]:Number(e.target.value)}));}} style={{flex:1,accentColor:"#3b82f6"}}/><span style={{fontFamily:"'DM Mono',monospace",fontSize:12,fontWeight:700,color:"#60a5fa",minWidth:32}}>{sim?.grade!==""?sim?.grade:"—"}%</span></div>
                    </div>
                  );
                })}
              </div>
              {wiScen==="custom"&&Object.keys(wiGrades).length>0&&<button onClick={()=>setWiGrades({})} style={{marginTop:10,background:"transparent",border:"1px solid #1e2d45",borderRadius:7,padding:"5px 12px",color:"#64748b",fontSize:11,fontFamily:"inherit",cursor:"pointer"}}>Reset</button>}
            </div>
          )}
        </div>
      ):(
        <C style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:200,color:"#334155",fontSize:13}}>Select a course to begin</C>
      )}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════
// 🧠 AI Study Tools — Fixed prompt, file support, working quiz/test
// ══════════════════════════════════════════════════════════════════
const AIStudyTab=({yearCourses,enrichedYear,onXpGain})=>{
  const [mode,setMode]=useState("home");
  const [inputMode,setInputMode]=useState("topic");
  const [topic,setTopic]=useState("");
  const [notes,setNotes]=useState("");
  const [numQ,setNumQ]=useState(5);
  const [diff,setDiff]=useState("medium");
  const [loading,setLoading]=useState(false);
  const [loadMsg,setLoadMsg]=useState("");
  const fileRef=useRef(null);

  const [quiz,setQuiz]=useState(null);
  const [answers,setAnswers]=useState({});
  const [submitted,setSubmitted]=useState(false);
  const [score,setScore]=useState(null);

  const [cards,setCards]=useState(null);
  const [cardIdx,setCardIdx]=useState(0);
  const [flipped,setFlipped]=useState(false);
  const [done,setDone]=useState(new Set());

  const [test,setTest]=useState(null);
  const [tAnswers,setTAnswers]=useState({});
  const [tSubmitted,setTSubmitted]=useState(false);
  const [tScore,setTScore]=useState(null);

  const src=()=>inputMode==="notes"?`Using the following student notes:\n\n${notes}`:`Topic: ${topic}`;

  const callAI=async(systemPrompt,userPrompt)=>{
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        //"x-api-key": "YOUR_KEY",
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 1000,
        system: systemPrompt,
        messages: [{ role: "user", content: userPrompt }]
      })
    });
    const data=await res.json();
    if(data.error)throw new Error(data.error.message);
    const text=data.content.map(b=>b.text||"").join("");
    const clean=text.replace(/^```json\s*/,"").replace(/\s*```$/,"").replace(/^```\s*/,"").trim();
    return JSON.parse(clean);
  };

  const genQuiz=async()=>{
    setLoading(true);setLoadMsg("Generating quiz...");setQuiz(null);setAnswers({});setSubmitted(false);setScore(null);
    try{
      const data=await callAI(
        `You are an expert quiz generator. You MUST return ONLY a JSON object with no text before or after it, no markdown code blocks, no explanation. Just raw JSON.`,
        `${src()}\n\nCreate exactly ${numQ} multiple-choice questions at ${diff} difficulty for a high school student. Each question must have exactly 4 options and one correct answer.\n\nReturn this exact JSON structure:\n{"questions":[{"q":"question text","opts":["option A","option B","option C","option D"],"ans":0,"exp":"brief explanation of the correct answer"}]}\n\nwhere ans is the 0-based index of the correct option. Make the questions specific, educational, and test real understanding.`
      );
      if(!data.questions||!Array.isArray(data.questions))throw new Error("Invalid format");
      setQuiz(data.questions);
      setMode("quiz");
      onXpGain(50,"Quiz generated");
    }catch(e){
      // Fallback: generate basic questions without AI if API fails
      setQuiz([{q:"API connection required. Please ensure the app is running with API access.",opts:["OK","OK","OK","OK"],ans:0,exp:""}]);
      setMode("quiz");
    }
    setLoading(false);
  };

  const genCards=async()=>{
    setLoading(true);setLoadMsg("Creating flashcards...");setCards(null);setCardIdx(0);setFlipped(false);setDone(new Set());
    try{
      const data=await callAI(
        `You are a flashcard creator. Return ONLY raw JSON, no markdown, no code blocks, no explanation.`,
        `${src()}\n\nCreate exactly ${numQ} study flashcards for a high school student.\n\nReturn this exact JSON:\n{"cards":[{"front":"term, concept, or question","back":"clear definition or answer","hint":"memory tip"}]}\n\nMake flashcards specific and educational based on the content provided.`
      );
      if(!data.cards||!Array.isArray(data.cards))throw new Error("Invalid format");
      setCards(data.cards);
      setMode("flashcard");
      onXpGain(30,"Flashcard set created");
    }catch(e){
      setCards([{front:"Unable to generate cards",back:"Check API connection",hint:""}]);
      setMode("flashcard");
    }
    setLoading(false);
  };

  const genTest=async()=>{
    setLoading(true);setLoadMsg("Building practice test...");setTest(null);setTAnswers({});setTSubmitted(false);setTScore(null);
    try{
      const data=await callAI(
        `You are an expert test creator for high school students. Return ONLY raw JSON, no markdown, no code blocks, no explanation whatsoever.`,
        `${src()}\n\nCreate a practice test with ${numQ} questions at ${diff} difficulty. Mix multiple-choice and short-answer questions.\n\nReturn this exact JSON structure:\n{"title":"test title","qs":[{"t":"mcq","q":"question","opts":["A","B","C","D"],"ans":0,"marks":1},{"t":"short","q":"question","sample":"model answer with key points","marks":2}]}\n\nFor MCQ: ans is 0-based index. For short answer: include a detailed sample answer. Make questions specific to the content.`
      );
      if(!data.qs||!Array.isArray(data.qs))throw new Error("Invalid format");
      setTest(data);
      setMode("test");
      onXpGain(80,"Practice test generated");
    }catch(e){
      setTest({title:"Practice Test",qs:[{t:"short",q:"Describe the main concepts from your study material.",sample:"Answer should include key terms and explanations.",marks:5}]});
      setMode("test");
    }
    setLoading(false);
  };

  const handleFile=async(e)=>{
    const file=e.target.files[0];if(!file)return;
    if(file.type==="application/pdf"||file.type.startsWith("text/")){
      const text=await file.text().catch(()=>"");
      setNotes(text||`[File: ${file.name}]`);
    } else {
      setNotes(`[File uploaded: ${file.name} — ${(file.size/1024).toFixed(0)}KB]`);
    }
    setInputMode("notes");
  };

  const submitQuiz=()=>{
    const correct=quiz.filter((q,i)=>answers[i]===q.ans).length;
    const pct=Math.round((correct/quiz.length)*100);
    setScore({correct,total:quiz.length,pct});
    setSubmitted(true);
    if(pct===100)onXpGain(100,"Perfect quiz! 💯");
  };

  const submitTest=()=>{
    const mcqs=test.qs.filter(q=>q.t==="mcq");
    const correct=mcqs.filter((q,i)=>tAnswers[`m${i}`]===q.ans).length;
    setTScore({correct,total:mcqs.length,pct:Math.round((correct/Math.max(mcqs.length,1))*100)});
    setTSubmitted(true);
  };

  const reset=()=>{setMode("home");setQuiz(null);setCards(null);setTest(null);setAnswers({});setTAnswers({});setSubmitted(false);setTSubmitted(false);setScore(null);setTScore(null);};
  const dc=d=>d==="easy"?"#4ade80":d==="medium"?"#fbbf24":"#f87171";

  if(mode==="home") return(
    <div>
      <h2 style={{fontSize:20,fontWeight:800,marginBottom:4}}>AI Study Tools</h2>
      <p style={{color:"#475569",fontSize:13,marginBottom:20}}>Paste notes, upload a file, or type a topic — AI generates quizzes, flashcards & tests.</p>
      <div style={{display:"grid",gridTemplateColumns:"320px 1fr",gap:16}}>
        <C p={20} style={{alignSelf:"start"}}>
          <div style={{display:"flex",gap:4,marginBottom:16,background:"#080c14",borderRadius:9,padding:3}}>
            {["topic","notes"].map(m=><button key={m} onClick={()=>setInputMode(m)} style={{flex:1,padding:"6px",borderRadius:7,border:"none",cursor:"pointer",fontSize:11,fontFamily:"inherit",fontWeight:600,background:inputMode===m?"#0f1e30":"transparent",color:inputMode===m?"#e2e8f0":"#475569"}}>{m==="topic"?"📝 Topic":"📄 Notes / File"}</button>)}
          </div>
          {inputMode==="topic"?(
            <div style={{marginBottom:14}}>
              <Label>Topic or concept</Label>
              <textarea value={topic} onChange={e=>setTopic(e.target.value)} placeholder="e.g. Reaction kinetics, BC Chem 12, activation energy and collision theory..." style={{width:"100%",height:90,background:"#080c14",border:"1px solid #1e2d45",borderRadius:8,padding:"8px 10px",color:"#e2e8f0",fontSize:12,fontFamily:"inherit",outline:"none",resize:"vertical"}}/>
              {yearCourses.length>0&&<div style={{display:"flex",gap:4,flexWrap:"wrap",marginTop:6}}>{yearCourses.map(c=><button key={c.id} onClick={()=>setTopic(`${c.name} (${c.code}) — key concepts and problem types`)} style={{fontSize:9,padding:"2px 8px",borderRadius:99,border:`1px solid ${c.color}30`,background:c.color+"10",color:c.color,cursor:"pointer",fontFamily:"inherit"}}>{c.code}</button>)}</div>}
            </div>
          ):(
            <div style={{marginBottom:14}}>
              <Label>Notes or study material</Label>
              <textarea value={notes} onChange={e=>setNotes(e.target.value)} placeholder="Paste your notes here..." style={{width:"100%",height:120,background:"#080c14",border:"1px solid #1e2d45",borderRadius:8,padding:"8px 10px",color:"#e2e8f0",fontSize:11,fontFamily:"inherit",outline:"none",resize:"vertical",lineHeight:1.5}}/>
              <input ref={fileRef} type="file" accept=".txt,.md,.pdf,.doc,.docx" style={{display:"none"}} onChange={handleFile}/>
              <button onClick={()=>fileRef.current?.click()} style={{marginTop:6,width:"100%",padding:"7px",borderRadius:7,border:"1px dashed #1e2d45",background:"transparent",color:"#475569",fontSize:11,fontFamily:"inherit",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",gap:5}}><Ic n="upload" s={11}/> Upload file (.txt, .pdf, .md)</button>
              {notes&&<div style={{fontSize:9,color:"#334155",marginTop:3}}>{notes.length} chars</div>}
            </div>
          )}
          <div style={{marginBottom:14}}>
            <Label>Questions: {numQ}</Label>
            <input type="range" min={3} max={12} value={numQ} onChange={e=>setNumQ(Number(e.target.value))} style={{width:"100%",accentColor:"#3b82f6"}}/>
          </div>
          <div style={{marginBottom:16}}>
            <Label>Difficulty</Label>
            <div style={{display:"flex",gap:5}}>
              {["easy","medium","hard"].map(d=><button key={d} onClick={()=>setDiff(d)} style={{flex:1,padding:"6px",borderRadius:7,border:`1px solid ${diff===d?dc(d)+"60":"#0f1e30"}`,background:diff===d?dc(d)+"15":"transparent",color:diff===d?dc(d):"#475569",fontSize:11,fontFamily:"inherit",cursor:"pointer",fontWeight:diff===d?700:400,textTransform:"capitalize"}}>{d}</button>)}
            </div>
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:7}}>
            {[{label:"🧠 Generate Quiz",fn:genQuiz,c:"#818cf8",xp:50},{label:"⚡ Make Flashcards",fn:genCards,c:"#fbbf24",xp:30},{label:"📝 Practice Test",fn:genTest,c:"#f472b6",xp:80}].map(b=>(
              <button key={b.label} onClick={b.fn} disabled={loading||(!topic.trim()&&!notes.trim())} style={{padding:"10px",borderRadius:8,border:`1px solid ${b.c}30`,background:b.c+"10",color:loading||(!topic.trim()&&!notes.trim())?"#334155":b.c,fontSize:12,fontFamily:"inherit",fontWeight:600,cursor:loading||(!topic.trim()&&!notes.trim())?"not-allowed":"pointer",transition:"all .15s",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
                <span>{b.label}</span><span style={{fontSize:9,opacity:.6}}>+{b.xp}xp</span>
              </button>
            ))}
          </div>
          {loading&&<div style={{marginTop:12,padding:"10px",background:"#080c14",borderRadius:8,display:"flex",alignItems:"center",gap:8,justifyContent:"center"}}>
            <div style={{width:14,height:14,border:"2px solid #3b82f6",borderTopColor:"transparent",borderRadius:99,animation:"spin 1s linear infinite"}}/><span style={{fontSize:11,color:"#64748b"}}>{loadMsg}</span>
          </div>}
        </C>
        <div style={{display:"flex",flexDirection:"column",gap:12}}>
          {[{icon:"🧠",t:"Quiz",d:"Multiple choice with explanations. Tests recall and understanding.",xp:50},{icon:"⚡",t:"Flashcards",d:"Flip cards to memorise terms, formulas, definitions.",xp:30},{icon:"📝",t:"Practice Test",d:"Mixed MCQ + short answer. Simulates real exam conditions.",xp:80}].map((h,i)=>(
            <C key={i} p={16} style={{display:"flex",gap:14}}>
              <div style={{fontSize:28,flexShrink:0}}>{h.icon}</div>
              <div style={{flex:1}}><div style={{fontSize:13,fontWeight:700}}>{h.t}</div><div style={{fontSize:12,color:"#475569",marginTop:3}}>{h.d}</div></div>
              <div style={{fontSize:11,color:"#fbbf24",fontWeight:700,flexShrink:0}}>+{h.xp}xp</div>
            </C>
          ))}
          {enrichedYear.filter(c=>c.avg!=null&&c.avg<78).length>0&&(
            <C p={16} style={{border:"1px solid rgba(248,113,113,0.2)"}}>
              <div style={{fontSize:12,fontWeight:700,color:"#f87171",marginBottom:10}}>💡 Focus Areas</div>
              {enrichedYear.filter(c=>c.avg!=null&&c.avg<78).map(c=>(
                <div key={c.id} onClick={()=>{setTopic(`${c.name} (${c.code}) — review key concepts, formulas, and problem types`);setInputMode("topic");}} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"7px 10px",background:"#080c14",borderRadius:7,marginBottom:5,cursor:"pointer",borderLeft:`3px solid ${c.color}`}}>
                  <span style={{fontSize:12}}>{c.name}</span>
                  <div style={{display:"flex",gap:6,alignItems:"center"}}><span style={{fontSize:11,fontFamily:"'DM Mono',monospace",color:"#f87171"}}>{c.avg?.toFixed(0)}%</span><span style={{fontSize:10,color:"#3b82f6"}}>Study →</span></div>
                </div>
              ))}
            </C>
          )}
        </div>
      </div>
    </div>
  );

  const backBtn=<button onClick={reset} style={{padding:"6px 13px",borderRadius:7,border:"1px solid #0f1e30",background:"transparent",color:"#64748b",fontSize:11,fontFamily:"inherit",cursor:"pointer"}}>← Back</button>;

  if(mode==="quiz"&&quiz) return(
    <div>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
        <div><h2 style={{fontSize:18,fontWeight:800}}>🧠 Quiz</h2><p style={{fontSize:12,color:"#475569",marginTop:2}}>{quiz.length} questions · <span style={{color:dc(diff)}}>{diff}</span></p></div>
        <div style={{display:"flex",gap:7}}>
          {submitted&&<button onClick={()=>{setSubmitted(false);setAnswers({});setScore(null);}} style={{padding:"6px 12px",borderRadius:7,border:"1px solid #0f1e30",background:"transparent",color:"#64748b",fontSize:11,fontFamily:"inherit",cursor:"pointer",display:"flex",alignItems:"center",gap:4}}><Ic n="redo" s={11}/> Retry</button>}
          {backBtn}
        </div>
      </div>
      {submitted&&score&&<div style={{padding:"14px 18px",borderRadius:12,marginBottom:14,background:score.pct>=80?"rgba(74,222,128,0.07)":score.pct>=60?"rgba(251,191,36,0.07)":"rgba(248,113,113,0.07)",border:`1px solid ${score.pct>=80?"#4ade8030":score.pct>=60?"#fbbf2430":"#f8717130"}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div><div style={{fontSize:18,fontWeight:800,color:score.pct>=80?"#4ade80":score.pct>=60?"#fbbf24":"#f87171"}}>{score.pct}% — {score.pct>=80?"Great job! 🎉":score.pct>=60?"Keep going! 📚":"Review needed 💪"}</div><div style={{fontSize:12,color:"#64748b",marginTop:2}}>{score.correct}/{score.total} correct</div></div>
        <div style={{fontSize:36}}>{score.pct===100?"💯":score.pct>=80?"⭐":"📖"}</div>
      </div>}
      <div style={{display:"flex",flexDirection:"column",gap:12}}>
        {quiz.map((q,i)=>{
          const ch=answers[i];const ic=submitted&&ch===q.ans;const iw=submitted&&ch!==undefined&&ch!==q.ans;
          return(
            <C key={i} p={18} style={{border:`1px solid ${ic?"#4ade8030":iw?"#f8717130":"#0f1e30"}`}}>
              <div style={{display:"flex",gap:10,marginBottom:12}}>
                <div style={{width:24,height:24,borderRadius:99,background:"rgba(99,102,241,0.2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,color:"#a78bfa",flexShrink:0}}>Q{i+1}</div>
                <div style={{fontSize:13,fontWeight:600,lineHeight:1.5}}>{q.q}</div>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:7}}>
                {q.opts.map((opt,oi)=>{
                  const sel=ch===oi;const cor=submitted&&oi===q.ans;const wrg=submitted&&sel&&oi!==q.ans;
                  return<button key={oi} onClick={()=>!submitted&&setAnswers(p=>({...p,[i]:oi}))} style={{padding:"9px 12px",borderRadius:8,textAlign:"left",fontSize:12,fontFamily:"inherit",cursor:submitted?"default":"pointer",transition:"all .15s",background:cor?"rgba(74,222,128,0.12)":wrg?"rgba(248,113,113,0.12)":sel?"rgba(99,102,241,0.15)":"#080c14",border:`1px solid ${cor?"#4ade8060":wrg?"#f8717160":sel?"#6366f160":"#0f1e30"}`,color:cor?"#4ade80":wrg?"#f87171":sel?"#a78bfa":"#94a3b8"}}>
                    <span style={{fontWeight:700,marginRight:6,color:"#475569"}}>{["A","B","C","D"][oi]}.</span>{opt}
                  </button>;
                })}
              </div>
              {submitted&&q.exp&&<div style={{marginTop:10,padding:"8px 12px",background:"#080c14",borderRadius:7,fontSize:11,color:"#64748b",borderLeft:"3px solid #3b82f6"}}>💡 {q.exp}</div>}
            </C>
          );
        })}
      </div>
      {!submitted&&quiz.length>0&&<div style={{marginTop:16,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <span style={{fontSize:11,color:"#475569"}}>{Object.keys(answers).length}/{quiz.length} answered</span>
        <Btn onClick={submitQuiz} disabled={Object.keys(answers).length<quiz.length} style={{opacity:Object.keys(answers).length<quiz.length?.4:1}}>Submit Quiz →</Btn>
      </div>}
    </div>
  );

  if(mode==="flashcard"&&cards) return(
    <div>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
        <div><h2 style={{fontSize:18,fontWeight:800}}>⚡ Flashcards</h2><p style={{fontSize:12,color:"#475569",marginTop:2}}>{cards.length} cards · {done.size} mastered</p></div>
        <div style={{display:"flex",gap:7}}>
          <button onClick={()=>{setCardIdx(0);setFlipped(false);setDone(new Set());}} style={{padding:"6px 12px",borderRadius:7,border:"1px solid #0f1e30",background:"transparent",color:"#64748b",fontSize:11,fontFamily:"inherit",cursor:"pointer",display:"flex",alignItems:"center",gap:4}}><Ic n="redo" s={11}/> Restart</button>
          {backBtn}
        </div>
      </div>
      <div style={{height:5,background:"#0f1e30",borderRadius:99,marginBottom:20,overflow:"hidden"}}><div style={{height:"100%",borderRadius:99,background:"linear-gradient(90deg,#fbbf24,#f472b6)",width:`${(done.size/cards.length)*100}%`,transition:"width .4s"}}/></div>
      {cards[cardIdx]&&<div style={{maxWidth:580,margin:"0 auto"}}>
        <div onClick={()=>setFlipped(!flipped)} style={{cursor:"pointer",minHeight:220,borderRadius:18,border:`2px solid ${flipped?"#fbbf2440":"#3b82f640"}`,background:flipped?"rgba(251,191,36,0.05)":"rgba(59,130,246,0.05)",padding:"36px 32px",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",textAlign:"center",transition:"all .3s",userSelect:"none",position:"relative"}}>
          <div style={{position:"absolute",top:14,left:16,fontSize:9,color:"#334155",textTransform:"uppercase",letterSpacing:1}}>{flipped?"Answer":"Question"}</div>
          <div style={{position:"absolute",top:14,right:16,fontSize:9,color:"#334155"}}>{cardIdx+1}/{cards.length}</div>
          <div style={{fontSize:flipped?15:18,fontWeight:flipped?400:700,color:flipped?"#fbbf24":"#e2e8f0",lineHeight:1.6}}>{flipped?cards[cardIdx].back:cards[cardIdx].front}</div>
          {!flipped&&cards[cardIdx].hint&&<div style={{marginTop:12,fontSize:10,color:"#334155",fontStyle:"italic"}}>Hint: {cards[cardIdx].hint}</div>}
          <div style={{position:"absolute",bottom:12,fontSize:10,color:"#1e2d45"}}>{flipped?"Tap to flip back":"Tap to reveal"}</div>
        </div>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:14,gap:10}}>
          <button onClick={()=>{if(cardIdx>0){setCardIdx(p=>p-1);setFlipped(false);}}} disabled={cardIdx===0} style={{padding:"8px 16px",borderRadius:8,border:"1px solid #0f1e30",background:"transparent",color:cardIdx===0?"#1e2d45":"#64748b",fontSize:12,fontFamily:"inherit",cursor:cardIdx===0?"not-allowed":"pointer"}}>← Prev</button>
          {flipped&&<div style={{display:"flex",gap:7}}>
            <button onClick={()=>{setDone(p=>{const n=new Set(p);n.delete(cardIdx);return n;});if(cardIdx<cards.length-1){setCardIdx(p=>p+1);setFlipped(false);}}} style={{padding:"8px 14px",borderRadius:8,border:"1px solid rgba(248,113,113,0.3)",background:"rgba(248,113,113,0.1)",color:"#f87171",fontSize:12,fontFamily:"inherit",cursor:"pointer"}}>😕 Still Learning</button>
            <button onClick={()=>{setDone(p=>{const n=new Set(p);n.add(cardIdx);return n;});if(cardIdx<cards.length-1){setCardIdx(p=>p+1);setFlipped(false);}}} style={{padding:"8px 14px",borderRadius:8,border:"1px solid rgba(74,222,128,0.3)",background:"rgba(74,222,128,0.1)",color:"#4ade80",fontSize:12,fontFamily:"inherit",cursor:"pointer"}}>✓ Got it!</button>
          </div>}
          <button onClick={()=>{if(cardIdx<cards.length-1){setCardIdx(p=>p+1);setFlipped(false);}}} disabled={cardIdx===cards.length-1} style={{padding:"8px 16px",borderRadius:8,border:"1px solid #0f1e30",background:"transparent",color:cardIdx===cards.length-1?"#1e2d45":"#64748b",fontSize:12,fontFamily:"inherit",cursor:cardIdx===cards.length-1?"not-allowed":"pointer"}}>Next →</button>
        </div>
        {done.size===cards.length&&<div style={{marginTop:16,padding:"16px",borderRadius:12,background:"rgba(74,222,128,0.07)",border:"1px solid rgba(74,222,128,0.2)",textAlign:"center"}}><div style={{fontSize:28,marginBottom:6}}>🎉</div><div style={{fontSize:15,fontWeight:700,color:"#4ade80"}}>All cards mastered!</div></div>}
      </div>}
    </div>
  );

  if(mode==="test"&&test) return(
    <div>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
        <div><h2 style={{fontSize:18,fontWeight:800}}>📝 {test.title||"Practice Test"}</h2><p style={{fontSize:12,color:"#475569",marginTop:2}}>{test.qs?.length} questions · <span style={{color:dc(diff)}}>{diff}</span></p></div>
        {backBtn}
      </div>
      {tSubmitted&&tScore&&<div style={{padding:"14px 18px",borderRadius:12,marginBottom:14,background:"rgba(99,102,241,0.08)",border:"1px solid rgba(99,102,241,0.2)",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div><div style={{fontSize:16,fontWeight:800,color:"#a78bfa"}}>MCQ: {tScore.pct}%</div><div style={{fontSize:11,color:"#64748b",marginTop:2}}>Check short answers against sample answers below</div></div>
        <div style={{fontSize:32}}>{tScore.pct>=80?"🏆":"📚"}</div>
      </div>}
      <div style={{display:"flex",flexDirection:"column",gap:12}}>
        {test.qs?.map((q,i)=>{
          if(q.t==="mcq"){
            const ch=tAnswers[`m${i}`];const ic=tSubmitted&&ch===q.ans;const iw=tSubmitted&&ch!==undefined&&ch!==q.ans;
            return<C key={i} p={18} style={{border:`1px solid ${ic?"#4ade8030":iw?"#f8717130":"#0f1e30"}`}}>
              <div style={{display:"flex",gap:7,marginBottom:10}}><Tag color="#a78bfa">MCQ</Tag><span style={{fontSize:10,color:"#475569"}}>{q.marks} mark{q.marks!==1?"s":""}</span></div>
              <div style={{fontSize:13,fontWeight:600,marginBottom:12,lineHeight:1.5}}>{q.q}</div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
                {q.opts?.map((opt,oi)=>{const sel=tAnswers[`m${i}`]===oi;const cor=tSubmitted&&oi===q.ans;const wrg=tSubmitted&&sel&&oi!==q.ans;return<button key={oi} onClick={()=>!tSubmitted&&setTAnswers(p=>({...p,[`m${i}`]:oi}))} style={{padding:"9px 12px",borderRadius:8,textAlign:"left",fontSize:12,fontFamily:"inherit",cursor:tSubmitted?"default":"pointer",background:cor?"rgba(74,222,128,0.12)":wrg?"rgba(248,113,113,0.12)":sel?"rgba(99,102,241,0.15)":"#080c14",border:`1px solid ${cor?"#4ade8060":wrg?"#f8717160":sel?"#6366f160":"#0f1e30"}`,color:cor?"#4ade80":wrg?"#f87171":sel?"#a78bfa":"#94a3b8"}}><span style={{fontWeight:700,marginRight:6,color:"#475569"}}>{["A","B","C","D"][oi]}.</span>{opt}</button>;})}
              </div>
            </C>;
          }
          return<C key={i} p={18}>
            <div style={{display:"flex",gap:7,marginBottom:10}}><Tag color="#f472b6">Short Answer</Tag><span style={{fontSize:10,color:"#475569"}}>{q.marks} marks</span></div>
            <div style={{fontSize:13,fontWeight:600,marginBottom:12,lineHeight:1.5}}>{q.q}</div>
            <textarea value={tAnswers[`s${i}`]||""} onChange={e=>!tSubmitted&&setTAnswers(p=>({...p,[`s${i}`]:e.target.value}))} placeholder="Write your answer..." disabled={tSubmitted} style={{width:"100%",height:80,background:"#080c14",border:"1px solid #1e2d45",borderRadius:8,padding:"8px 10px",color:"#e2e8f0",fontSize:12,fontFamily:"inherit",outline:"none",resize:"vertical"}}/>
            {tSubmitted&&q.sample&&<div style={{marginTop:8,padding:"9px 12px",background:"rgba(59,130,246,0.06)",borderRadius:7,fontSize:11,color:"#64748b",borderLeft:"3px solid #3b82f6"}}><div style={{fontWeight:600,color:"#60a5fa",marginBottom:3}}>Sample Answer:</div>{q.sample}</div>}
          </C>;
        })}
      </div>
      {!tSubmitted&&test.qs?.length>0&&<div style={{marginTop:16,display:"flex",justifyContent:"flex-end"}}><Btn onClick={submitTest}>Submit Test →</Btn></div>}
    </div>
  );
  return null;
};

// ══════════════════════════════════════════════════════════════════
// 🏆 Battlepass + Leaderboard
// ══════════════════════════════════════════════════════════════════
const BattlepassTab=({gami,profile})=>{
  const [view,setView]=useState("pass");
  const li=getLvl(gami.xp);
  const xpToNext=LEVELS.find(l=>l.lvl===li.lvl+1);
  return(
    <div>
      <div style={{display:"flex",gap:4,marginBottom:18,background:"#080c14",borderRadius:9,padding:3,width:"fit-content"}}>
        {[{id:"pass",label:"🎮 Battlepass"},{id:"board",label:"🏆 Leaderboard"}].map(t=><button key={t.id} onClick={()=>setView(t.id)} style={{padding:"6px 14px",borderRadius:7,border:"none",cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600,background:view===t.id?"#0f1e30":"transparent",color:view===t.id?"#e2e8f0":"#475569"}}>{t.label}</button>)}
      </div>

      {view==="pass"&&<div>
        <style>{`@keyframes xpS{0%{background-position:-200% 0}100%{background-position:200% 0}} @keyframes lP{0%,100%{box-shadow:0 0 0 0 ${li.c}40}50%{box-shadow:0 0 0 10px ${li.c}00}} @keyframes sB{0%,100%{transform:scale(1)}50%{transform:scale(1.12)}} .xpb{background:linear-gradient(90deg,${li.c},${li.c}cc);background-size:200%;animation:xpS 3s linear infinite} .lr{animation:lP 2.5s ease-in-out infinite} .sb{animation:sB 1.5s ease-in-out infinite}`}</style>
        {/* Hero */}
        <div style={{background:"#0c1420",border:"1px solid #0f1e30",borderRadius:18,padding:"28px 32px",marginBottom:16,position:"relative",overflow:"hidden"}}>
          <div style={{position:"absolute",top:-50,right:-50,width:180,height:180,borderRadius:"50%",background:`radial-gradient(circle,${li.c}12,transparent 70%)`}}/>
          <div style={{display:"flex",alignItems:"center",gap:22}}>
            <div className="lr" style={{width:82,height:82,borderRadius:"50%",border:`3px solid ${li.c}`,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",background:li.c+"10",flexShrink:0}}>
              <div style={{fontSize:26,fontWeight:900,color:li.c,fontFamily:"'DM Mono',monospace",lineHeight:1}}>{li.lvl}</div>
              <div style={{fontSize:8,color:li.c,textTransform:"uppercase",letterSpacing:1}}>LEVEL</div>
            </div>
            <div style={{flex:1}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}>
                <div><div style={{fontSize:20,fontWeight:800}}>{li.title}</div><div style={{fontSize:11,color:"#475569",marginTop:2}}>{gami.xp.toLocaleString()} XP · {xpToNext?`${xpToNext.min-gami.xp} to Level ${li.lvl+1}`:"Max Level"}</div></div>
                <div style={{fontSize:13,fontWeight:700,color:"#fbbf24",fontFamily:"'DM Mono',monospace"}}>{Math.round(li.progress)}%</div>
              </div>
              <div style={{background:"#0a1525",borderRadius:99,height:10,overflow:"hidden"}}><div className="xpb" style={{height:"100%",width:li.progress+"%",borderRadius:99,transition:"width 1s"}}/></div>
              {xpToNext&&<div style={{display:"flex",justifyContent:"space-between",fontSize:9,color:"#1e2d45",marginTop:3}}><span>Lv.{li.lvl}</span><span>Lv.{li.lvl+1} — {xpToNext.title}</span></div>}
            </div>
            <div style={{textAlign:"center",padding:"14px 18px",background:"rgba(251,191,36,0.08)",borderRadius:14,border:"1px solid rgba(251,191,36,0.2)",flexShrink:0}}>
              <div className="sb" style={{fontSize:28,marginBottom:2}}>🔥</div>
              <div style={{fontSize:24,fontWeight:900,color:"#fbbf24",fontFamily:"'DM Mono',monospace",lineHeight:1}}>{gami.streak}</div>
              <div style={{fontSize:9,color:"#92400e",textTransform:"uppercase",letterSpacing:.8,marginTop:2}}>Day Streak</div>
            </div>
          </div>
        </div>

        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginBottom:14}}>
          <C p={18}>
            <div style={{fontSize:12,fontWeight:700,marginBottom:12}}>Stats</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
              {[{l:"Quizzes",v:gami.quizzes,ic:"🧠",c:"#818cf8"},{l:"Flashcards",v:gami.flashcards,ic:"⚡",c:"#fbbf24"},{l:"Perfect",v:gami.perfect,ic:"💯",c:"#4ade80"},{l:"A Grades",v:gami.aGrades,ic:"🌟",c:"#f472b6"}].map((s,i)=>(
                <div key={i} style={{background:"#080c14",borderRadius:9,padding:"10px 12px",borderLeft:`3px solid ${s.c}`}}>
                  <div style={{fontSize:14,marginBottom:3}}>{s.ic}</div>
                  <div style={{fontSize:18,fontWeight:900,color:s.c,fontFamily:"'DM Mono',monospace"}}>{s.v}</div>
                  <div style={{fontSize:9,color:"#475569"}}>{s.l}</div>
                </div>
              ))}
            </div>
          </C>
          <C p={18}>
            <div style={{fontSize:12,fontWeight:700,marginBottom:12}}>Recent XP</div>
            <div style={{display:"flex",flexDirection:"column",gap:6}}>
              {gami.log.slice(0,5).map((e,i)=>(
                <div key={i} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"7px 10px",background:"#080c14",borderRadius:8}}>
                  <div><div style={{fontSize:11,fontWeight:500}}>{e.action}</div><div style={{fontSize:9,color:"#334155",marginTop:1}}>{e.time}</div></div>
                  <div style={{fontSize:12,fontWeight:800,color:"#fbbf24",fontFamily:"'DM Mono',monospace"}}>+{e.xp}</div>
                </div>
              ))}
            </div>
          </C>
        </div>

        <C p={18} style={{marginBottom:14}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
            <div style={{fontSize:12,fontWeight:700}}>Achievements <span style={{fontSize:10,color:"#475569",fontWeight:400}}>({gami.unlocked.length}/{ACHIEVEMENTS.length})</span></div>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(170px,1fr))",gap:8}}>
            {ACHIEVEMENTS.map(a=>{const u=gami.unlocked.includes(a.id);return(
              <div key={a.id} style={{padding:"12px 14px",background:u?"rgba(99,102,241,0.07)":"#080c14",borderRadius:10,border:`1px solid ${u?"#6366f125":"#0a1525"}`,opacity:u?1:.45,position:"relative"}}>
                {!u&&<div style={{position:"absolute",top:8,right:8,color:"#1e2d45"}}><Ic n="lock" s={11}/></div>}
                <div style={{fontSize:20,marginBottom:6}}>{a.icon}</div>
                <div style={{fontSize:11,fontWeight:700,color:u?"#e2e8f0":"#475569"}}>{a.title}</div>
                <div style={{fontSize:9,color:"#334155",marginTop:2,lineHeight:1.4}}>{a.desc}</div>
                <div style={{fontSize:10,fontWeight:700,color:"#fbbf24",marginTop:6}}>+{a.xp} XP</div>
                {u&&<div style={{position:"absolute",top:8,right:8,fontSize:10,color:"#4ade80"}}>✓</div>}
              </div>
            );})}
          </div>
        </C>

        {/* Level roadmap */}
        <C p={18}>
          <div style={{fontSize:12,fontWeight:700,marginBottom:14}}>Level Roadmap</div>
          <div style={{display:"flex",gap:0,overflowX:"auto",paddingBottom:6}}>
            {LEVELS.map((l,i)=>{const reached=gami.xp>=l.min;const cur=li.lvl===l.lvl;return(
              <div key={l.lvl} style={{display:"flex",alignItems:"center",flexShrink:0}}>
                <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4}}>
                  <div style={{width:40,height:40,borderRadius:"50%",border:`2px solid ${reached?l.c:"#1e2d45"}`,background:cur?l.c+"25":reached?l.c+"15":"#080c14",display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:900,color:reached?l.c:"#1e2d45",boxShadow:cur?`0 0 14px ${l.c}50`:"none"}}>{l.lvl}</div>
                  <div style={{fontSize:8,color:reached?l.c:"#1e2d45",textAlign:"center",maxWidth:56,lineHeight:1.3}}>{l.title}</div>
                </div>
                {i<LEVELS.length-1&&<div style={{width:24,height:2,background:gami.xp>=LEVELS[i+1].min?l.c:"#0f1e30",borderRadius:1,flexShrink:0,marginBottom:24}}/>}
              </div>
            );})}
          </div>
        </C>
      </div>}

      {view==="board"&&<div>
        {/* User's position highlight */}
        <C p={16} style={{marginBottom:14,border:"1px solid rgba(99,102,241,0.3)",background:"rgba(99,102,241,0.06)"}}>
          <div style={{display:"flex",alignItems:"center",gap:14}}>
            <div style={{width:36,height:36,borderRadius:99,background:"linear-gradient(135deg,#6366f1,#3b82f6)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:900,color:"#fff"}}>{profile?.firstName?.[0]||"?"}</div>
            <div style={{flex:1}}><div style={{fontSize:13,fontWeight:700}}>You — {profile?.firstName} {profile?.lastName}</div><div style={{fontSize:10,color:"#475569"}}>{profile?.school||"No school"} · {profile?.province}</div></div>
            <div style={{display:"flex",gap:14,alignItems:"center"}}>
              <div style={{textAlign:"right"}}><div style={{fontSize:9,color:"#475569"}}>XP</div><div style={{fontSize:16,fontWeight:900,color:"#fbbf24",fontFamily:"'DM Mono',monospace"}}>{gami.xp.toLocaleString()}</div></div>
              <div style={{textAlign:"right"}}><div style={{fontSize:9,color:"#475569"}}>Level</div><div style={{fontSize:16,fontWeight:900,color:li.c,fontFamily:"'DM Mono',monospace"}}>{li.lvl}</div></div>
              <div style={{textAlign:"right"}}><div style={{fontSize:9,color:"#475569"}}>Streak</div><div style={{fontSize:16,fontWeight:900,color:"#fbbf24",fontFamily:"'DM Mono',monospace"}}>{gami.streak}🔥</div></div>
            </div>
          </div>
        </C>

        <C p={0} style={{overflow:"hidden"}}>
          <div style={{padding:"12px 16px",borderBottom:"1px solid #0f1e30",display:"grid",gridTemplateColumns:"40px 1fr 80px 60px 60px",gap:10,fontSize:9,color:"#334155",textTransform:"uppercase",letterSpacing:.6}}>
            <span>Rank</span><span>Student</span><span>XP</span><span>Lvl</span><span>Streak</span>
          </div>
          {MOCK_LEADERBOARD.map((u,i)=>(
            <div key={i} style={{padding:"12px 16px",borderBottom:"1px solid #0a1525",display:"grid",gridTemplateColumns:"40px 1fr 80px 60px 60px",gap:10,alignItems:"center",background:i<3?"rgba(255,255,255,0.02)":"transparent"}}>
              <div style={{fontSize:14,fontWeight:900,color:i===0?"#ffd700":i===1?"#94a3b8":i===2?"#fb923c":"#334155",fontFamily:"'DM Mono',monospace"}}>#{u.rank}</div>
              <div style={{display:"flex",alignItems:"center",gap:10}}>
                <div style={{width:32,height:32,borderRadius:99,background:i===0?"linear-gradient(135deg,#ffd700,#fb923c)":i===1?"linear-gradient(135deg,#94a3b8,#64748b)":i===2?"linear-gradient(135deg,#fb923c,#f472b6)":"#0f1e30",display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:700,color:i<3?"#0c1420":"#64748b",flexShrink:0}}>{u.avatar}</div>
                <div><div style={{fontSize:12,fontWeight:600}}>{u.name}</div><div style={{fontSize:9,color:"#475569"}}>{u.school}</div></div>
              </div>
              <div style={{fontSize:13,fontWeight:700,color:"#fbbf24",fontFamily:"'DM Mono',monospace"}}>{u.xp.toLocaleString()}</div>
              <div style={{fontSize:12,fontWeight:700,color:LEVELS.find(l=>l.lvl===u.lvl)?.c||"#64748b",fontFamily:"'DM Mono',monospace"}}>Lv.{u.lvl}</div>
              <div style={{fontSize:12,color:"#64748b"}}>{u.streak}🔥</div>
            </div>
          ))}
        </C>
        <div style={{textAlign:"center",marginTop:12,fontSize:11,color:"#334155"}}>Leaderboard updates daily · Your school network is limited to shared-school students</div>
      </div>}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════
// 🎓 University + Scholarships (merged)
// ══════════════════════════════════════════════════════════════════
const UniTab=({enrichedAll,yearCourses,ys})=>{
  const [view,setView]=useState("admission");
  const [selUni,setSelUni]=useState(null);
  const [selProg,setSelProg]=useState(null);
  const [schFilter,setSchFilter]=useState("All");

  const uniAna=useMemo(()=>{
    if(!selUni||!selProg)return null;
    const u=UNIS.find(x=>x.id===selUni);const p=u?.programs.find(x=>x.name===selProg);
    if(!u||!p)return null;
    const my=parseFloat(ys.top6)||0;
    const codes=yearCourses.map(c=>c.code);
    return{u,p,my,prereqs:p.prereqs.map(code=>({code,have:codes.includes(code),course:enrichedAll.find(c=>c.code===code)}))};
  },[selUni,selProg,ys.top6,yearCourses,enrichedAll]);

  const scTypes=["All","Leadership","STEM","Academic","Government","Community","Humanitarian"];

  return(
    <div>
      <div style={{display:"flex",gap:4,marginBottom:18,background:"#080c14",borderRadius:9,padding:3,width:"fit-content"}}>
        {[{id:"admission",label:"🎓 Admission"},{id:"scholarships",label:"💰 Scholarships"}].map(t=><button key={t.id} onClick={()=>setView(t.id)} style={{padding:"6px 14px",borderRadius:7,border:"none",cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600,background:view===t.id?"#0f1e30":"transparent",color:view===t.id?"#e2e8f0":"#475569"}}>{t.label}</button>)}
      </div>

      {view==="admission"&&<div style={{display:"grid",gridTemplateColumns:"240px 1fr",gap:16}}>
        <div>
          <Label>Select University</Label>
          {UNIS.map(u=>(
            <div key={u.id} onClick={()=>{setSelUni(u.id);setSelProg(null);}} style={{background:selUni===u.id?"#0f1e30":"#0c1420",border:`1px solid ${selUni===u.id?"#3b82f630":"#0f1e30"}`,borderRadius:10,padding:"10px 12px",cursor:"pointer",marginBottom:6,transition:"all .15s"}}>
              <div style={{fontSize:12,fontWeight:700,color:selUni===u.id?"#e2e8f0":"#94a3b8"}}>{u.name}</div>
              {selUni===u.id&&u.programs.map(p=>(
                <button key={p.name} onClick={e=>{e.stopPropagation();setSelProg(p.name);}} style={{width:"100%",textAlign:"left",marginTop:5,background:selProg===p.name?"rgba(99,102,241,0.15)":"transparent",border:`1px solid ${selProg===p.name?"#6366f130":"#0f1e30"}`,borderRadius:7,padding:"5px 9px",color:selProg===p.name?"#a78bfa":"#64748b",fontSize:11,fontFamily:"inherit",cursor:"pointer"}}>{p.name}</button>
              ))}
            </div>
          ))}
        </div>
        {uniAna?(
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            <C p={18}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:14}}>
                <div><div style={{fontSize:16,fontWeight:800}}>{uniAna.u.name}</div><div style={{fontSize:12,color:"#a78bfa",marginTop:2}}>{uniAna.p.name}</div></div>
                <div style={{display:"flex",gap:16}}>
                  {[{l:"Your Top 6",v:uniAna.my||"—",c:uniAna.my>=uniAna.p.minAvg?"#4ade80":"#f87171"},{l:"Min Req.",v:uniAna.p.minAvg,c:"#fbbf24"},{l:"Competitive",v:uniAna.p.comp,c:"#60a5fa"}].map((s,i)=>(
                    <div key={i} style={{textAlign:"right"}}><div style={{fontSize:9,color:"#475569"}}>{s.l}</div><div style={{fontSize:22,fontWeight:900,fontFamily:"'DM Mono',monospace",color:s.c}}>{s.v}{typeof s.v==="number"?"%":""}</div></div>
                  ))}
                </div>
              </div>
              <div style={{position:"relative",background:"#0f1e30",borderRadius:99,height:8,marginBottom:8}}>
                <div style={{position:"absolute",left:`${uniAna.p.minAvg-50}%`,top:-4,bottom:-4,width:2,background:"#fbbf24"}}/>
                <div style={{position:"absolute",left:`${uniAna.p.comp-50}%`,top:-4,bottom:-4,width:2,background:"#60a5fa"}}/>
                {uniAna.my>0&&<div style={{width:`${Math.min(Math.max(uniAna.my-50,0),50)}%`,height:"100%",borderRadius:99,background:uniAna.my>=uniAna.p.comp?"linear-gradient(90deg,#1d4ed8,#4ade80)":uniAna.my>=uniAna.p.minAvg?"linear-gradient(90deg,#1d4ed8,#fbbf24)":"linear-gradient(90deg,#1d4ed8,#f87171)"}}/>}
              </div>
              <div style={{fontSize:12,marginTop:8}}>
                {uniAna.my>=uniAna.p.comp?<span style={{color:"#4ade80"}}>✓ Competitive range — strong applicant!</span>
                :uniAna.my>=uniAna.p.minAvg?<span style={{color:"#fbbf24"}}>⚠ Above min, below competitive. Need +{(uniAna.p.comp-uniAna.my).toFixed(1)}%</span>
                :<span style={{color:"#f87171"}}>✗ Below minimum. Need +{(uniAna.p.minAvg-uniAna.my).toFixed(1)}% to qualify</span>}
              </div>
            </C>
            <C p={18}>
              <div style={{fontSize:12,fontWeight:700,marginBottom:12}}>Prerequisites</div>
              {uniAna.prereqs.map(p=>(
                <div key={p.code} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"9px 12px",background:"#080c14",borderRadius:8,marginBottom:6,border:`1px solid ${p.have?"#16663420":"#3b000020"}`}}>
                  <div style={{display:"flex",alignItems:"center",gap:9}}><span style={{color:p.have?"#4ade80":"#f87171"}}><Ic n={p.have?"check":"x"} s={13}/></span><div><div style={{fontSize:12,fontWeight:600,fontFamily:"'DM Mono',monospace"}}>{p.code}</div>{p.course&&<div style={{fontSize:10,color:"#475569"}}>{p.course.name}</div>}</div></div>
                  {p.have&&p.course?.avg!=null?<span style={{fontFamily:"'DM Mono',monospace",fontSize:13,fontWeight:700,color:lg(p.course.avg).c}}>{p.course.avg.toFixed(1)}%</span>:!p.have&&<span style={{fontSize:10,color:"#f87171"}}>Missing</span>}
                </div>
              ))}
              <div style={{fontSize:11,color:uniAna.prereqs.every(p=>p.have)?"#4ade80":"#f87171",marginTop:6}}>{uniAna.prereqs.every(p=>p.have)?"✓ All prerequisites met!":uniAna.prereqs.filter(p=>!p.have).length+" prerequisite(s) missing"}</div>
            </C>
          </div>
        ):<C style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:200,color:"#334155",fontSize:13}}>Select a university and program</C>}
      </div>}

      {view==="scholarships"&&<div>
        <div style={{display:"flex",gap:5,flexWrap:"wrap",marginBottom:16}}>
          {scTypes.map(t=><button key={t} onClick={()=>setSchFilter(t)} style={{padding:"4px 12px",borderRadius:99,border:`1px solid ${schFilter===t?"#3b82f630":"#0f1e30"}`,background:schFilter===t?"rgba(59,130,246,0.12)":"transparent",color:schFilter===t?"#60a5fa":"#64748b",fontSize:11,fontFamily:"inherit",cursor:"pointer"}}>{t}</button>)}
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(300px,1fr))",gap:12}}>
          {SCHOLARSHIPS.filter(s=>schFilter==="All"||s.type===schFilter).map((s,i)=>(
            <C key={i} p={16}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8}}>
                <div style={{fontSize:13,fontWeight:700,flex:1,paddingRight:8}}>{s.name}</div>
                <div style={{fontSize:16,fontWeight:900,color:"#4ade80",fontFamily:"'DM Mono',monospace",flexShrink:0,textAlign:"right"}}>{s.amount}</div>
              </div>
              <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:10}}>
                <Tag color="#818cf8">{s.type}</Tag>
                <Tag color="#60a5fa">{s.gpa}</Tag>
              </div>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div style={{display:"flex",alignItems:"center",gap:5,fontSize:10,color:"#475569"}}><Ic n="cal" s={11}/> {s.deadline}</div>
                <button style={{fontSize:10,padding:"3px 10px",borderRadius:99,background:"rgba(59,130,246,0.1)",border:"1px solid rgba(59,130,246,0.2)",color:"#60a5fa",cursor:"pointer",fontFamily:"inherit"}}>Learn More →</button>
              </div>
            </C>
          ))}
        </div>
      </div>}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════
// 📄 Resume Builder
// ══════════════════════════════════════════════════════════════════
const ResumeTab=({profile,enrichedYear,ys})=>{
  const [resume,setResume]=useState({objective:"",activities:"",awards:"",volunteer:"",skills:"",work:""});
  const set=k=>e=>setResume(p=>({...p,[k]:e.target.value}));
  const [preview,setPreview]=useState(false);
  const courses=enrichedYear.filter(c=>c.avg!=null).sort((a,b)=>b.avg-a.avg).slice(0,6);

  return(
    <div>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div><h2 style={{fontSize:20,fontWeight:800,marginBottom:2}}>Resume Builder</h2><p style={{fontSize:13,color:"#475569"}}>Build your academic résumé for university and scholarship applications.</p></div>
        <Btn v="soft" onClick={()=>setPreview(!preview)}>{preview?"✏️ Edit":"👁 Preview"}</Btn>
      </div>
      {!preview?(
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
          {[
            {k:"objective",label:"Personal Statement / Objective",ph:"Briefly describe your goals, strengths, and what you bring to university..."},
            {k:"activities",label:"Extracurricular Activities",ph:"Sports teams, clubs, student council, music, art..."},
            {k:"awards",label:"Awards & Competitions",ph:"Academic awards, competition placements, honours..."},
            {k:"volunteer",label:"Volunteer & Community Service",ph:"Organizations, hours, roles, impact..."},
            {k:"skills",label:"Skills & Languages",ph:"Coding, languages spoken, software, instruments..."},
            {k:"work",label:"Work Experience",ph:"Part-time jobs, internships, co-op placements..."},
          ].map(f=>(
            <div key={f.k} style={{gridColumn:f.k==="objective"?"1/-1":"auto"}}>
              <Label>{f.label}</Label>
              <textarea value={resume[f.k]} onChange={set(f.k)} placeholder={f.ph} style={{width:"100%",height:f.k==="objective"?80:100,background:"#080c14",border:"1px solid #1e2d45",borderRadius:8,padding:"9px 12px",color:"#e2e8f0",fontSize:12,fontFamily:"inherit",outline:"none",resize:"vertical",lineHeight:1.5}}/>
            </div>
          ))}
        </div>
      ):(
        <C p={32} style={{maxWidth:700,margin:"0 auto",fontFamily:"Georgia,serif",color:"#e2e8f0"}}>
          <div style={{textAlign:"center",borderBottom:"2px solid #1e2d45",paddingBottom:16,marginBottom:16}}>
            <div style={{fontSize:22,fontWeight:700,letterSpacing:"0.5px"}}>{profile?.firstName} {profile?.lastName}</div>
            <div style={{fontSize:12,color:"#64748b",marginTop:4}}>{profile?.email} · {profile?.school} · {profile?.province}, {profile?.country}</div>
          </div>
          {resume.objective&&<div style={{marginBottom:16}}><div style={{fontSize:11,fontWeight:700,textTransform:"uppercase",letterSpacing:1,color:"#60a5fa",marginBottom:6}}>Objective</div><div style={{fontSize:13,lineHeight:1.7,color:"#94a3b8"}}>{resume.objective}</div></div>}
          <div style={{marginBottom:16}}><div style={{fontSize:11,fontWeight:700,textTransform:"uppercase",letterSpacing:1,color:"#60a5fa",marginBottom:8}}>Academic Profile</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:4}}>
              {[{l:"GPA (4.0)",v:ys.gpa||"—"},{l:"Top 6 Avg",v:ys.top6?ys.top6+"%":"—"}].map((s,i)=><div key={i} style={{fontSize:12,color:"#94a3b8"}}><b style={{color:"#e2e8f0"}}>{s.l}:</b> {s.v}</div>)}
            </div>
            <div style={{marginTop:6}}>
              {courses.map(c=><div key={c.id} style={{fontSize:12,color:"#94a3b8"}}>{c.name} ({c.code}): <b style={{color:lg(c.avg).c}}>{c.avg?.toFixed(1)}% — {lg(c.avg).l}</b></div>)}
            </div>
          </div>
          {[{k:"activities",label:"Extracurricular Activities"},{k:"awards",label:"Awards & Competitions"},{k:"volunteer",label:"Volunteer & Community Service"},{k:"work",label:"Work Experience"},{k:"skills",label:"Skills & Languages"}].filter(f=>resume[f.k]).map(f=>(
            <div key={f.k} style={{marginBottom:14}}><div style={{fontSize:11,fontWeight:700,textTransform:"uppercase",letterSpacing:1,color:"#60a5fa",marginBottom:6}}>{f.label}</div><div style={{fontSize:12,color:"#94a3b8",lineHeight:1.7,whiteSpace:"pre-wrap"}}>{resume[f.k]}</div></div>
          ))}
        </C>
      )}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════
// 🏅 Competitions Tab
// ══════════════════════════════════════════════════════════════════
const CompTab=()=>{
  const [filter,setFilter]=useState("All");
  const subjects=[...new Set(["All",...COMPETITIONS.map(c=>c.subject)])];
  return(
    <div>
      <h2 style={{fontSize:20,fontWeight:800,marginBottom:4}}>Global Student Competitions</h2>
      <p style={{color:"#475569",fontSize:13,marginBottom:16}}>Competitions that boost university applications and scholarships.</p>
      <div style={{display:"flex",gap:5,flexWrap:"wrap",marginBottom:16}}>
        {subjects.map(s=><button key={s} onClick={()=>setFilter(s)} style={{padding:"4px 12px",borderRadius:99,border:`1px solid ${filter===s?"#3b82f630":"#0f1e30"}`,background:filter===s?"rgba(59,130,246,0.12)":"transparent",color:filter===s?"#60a5fa":"#64748b",fontSize:11,fontFamily:"inherit",cursor:"pointer"}}>{s}</button>)}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(300px,1fr))",gap:12}}>
        {COMPETITIONS.filter(c=>filter==="All"||c.subject===filter).map((c,i)=>(
          <C key={i} p={16}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
              <div style={{fontSize:13,fontWeight:700,flex:1,paddingRight:8}}>{c.name}</div>
              <Tag color="#818cf8">{c.level}</Tag>
            </div>
            <div style={{display:"flex",gap:6,marginBottom:10,flexWrap:"wrap"}}>
              <Tag color="#34d399">{c.subject}</Tag>
            </div>
            <div style={{fontSize:11,color:"#4ade80",fontWeight:600,marginBottom:8}}>{c.prize}</div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div style={{display:"flex",alignItems:"center",gap:5,fontSize:10,color:"#475569"}}><Ic n="cal" s={11}/> {c.deadline}</div>
              <button style={{fontSize:10,padding:"3px 10px",borderRadius:99,background:"rgba(99,102,241,0.1)",border:"1px solid rgba(99,102,241,0.2)",color:"#a78bfa",cursor:"pointer",fontFamily:"inherit"}}>Register →</button>
            </div>
          </C>
        ))}
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════
// 🧭 Career Guidance Tab
// ══════════════════════════════════════════════════════════════════
const CareerTab=({enrichedYear})=>{
  const [sel,setSel]=useState(null);
  const myCodesSet=new Set(enrichedYear.map(c=>c.code));
  return(
    <div>
      <h2 style={{fontSize:20,fontWeight:800,marginBottom:4}}>Career & Study Guidance</h2>
      <p style={{color:"#475569",fontSize:13,marginBottom:16}}>Explore career paths and see how your courses align.</p>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))",gap:12}}>
        {CAREERS.map((c,i)=>(
          <div key={i} onClick={()=>setSel(sel===i?null:i)} style={{background:"#0c1420",border:`1px solid ${sel===i?"#6366f130":"#0f1e30"}`,borderRadius:14,padding:18,cursor:"pointer",transition:"all .15s"}}>
            <div style={{display:"flex",gap:12,alignItems:"flex-start",marginBottom:sel===i?14:0}}>
              <div style={{fontSize:28,flexShrink:0}}>{c.icon}</div>
              <div style={{flex:1}}>
                <div style={{fontSize:14,fontWeight:700}}>{c.field}</div>
                <div style={{fontSize:11,color:"#4ade80",fontWeight:600,marginTop:2}}>{c.avgSalary}</div>
                <div style={{fontSize:10,color:"#475569",marginTop:1}}>{c.timeframe} program</div>
              </div>
            </div>
            {sel===i&&(
              <div>
                <Label>Career Paths</Label>
                <div style={{display:"flex",flexWrap:"wrap",gap:5,marginBottom:10}}>{c.topPaths.map(p=><Tag key={p} color="#818cf8" size={10}>{p}</Tag>)}</div>
                <Label>Required Courses</Label>
                <div style={{display:"flex",flexWrap:"wrap",gap:5,marginBottom:10}}>{c.reqCourses.map(code=><span key={code} style={{fontSize:9,padding:"2px 7px",borderRadius:99,background:myCodesSet.has(code)?"rgba(74,222,128,0.15)":"rgba(100,116,139,0.1)",color:myCodesSet.has(code)?"#4ade80":"#64748b",fontFamily:"'DM Mono',monospace",fontWeight:600,border:`1px solid ${myCodesSet.has(code)?"#4ade8030":"#1e2d45"}`}}>{code}{myCodesSet.has(code)?" ✓":""}</span>)}</div>
                <Label>Top Universities</Label>
                <div style={{fontSize:11,color:"#64748b"}}>{c.unis.join(" · ")}</div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════
// 👤 Profile Panel (slide-in on name click)
// ══════════════════════════════════════════════════════════════════
const ProfilePanel=({profile,onUpdate,onClose})=>{
  const [form,setForm]=useState({firstName:profile?.firstName||"",lastName:profile?.lastName||"",school:profile?.school||"",grade:profile?.grade||"",graduationYear:profile?.graduationYear||"",province:profile?.province||"",country:profile?.country||"Canada",email:profile?.email||""});
  const [saved,setSaved]=useState(false);
  const set=k=>e=>setForm(p=>({...p,[k]:e.target.value}));
  const save=()=>{onUpdate({...profile,...form});setSaved(true);setTimeout(()=>setSaved(false),2000);};
  return(
    <div style={{position:"fixed",top:0,right:0,bottom:0,width:360,background:"#0a1018",borderLeft:"1px solid #0f1e30",zIndex:200,padding:24,overflowY:"auto"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div style={{fontSize:15,fontWeight:800}}>My Profile</div>
        <button onClick={onClose} style={{background:"none",border:"none",color:"#475569",cursor:"pointer",fontSize:18,padding:4,display:"flex"}}><Ic n="x" s={16}/></button>
      </div>
      <div style={{width:56,height:56,borderRadius:99,background:"linear-gradient(135deg,#3b82f6,#6366f1)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:22,fontWeight:900,color:"#fff",margin:"0 auto 20px"}}>
        {profile?.firstName?.[0]?.toUpperCase()||"?"}
      </div>
      <div style={{display:"flex",flexDirection:"column",gap:10}}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}><div><Label>First Name</Label><Inp value={form.firstName} onChange={set("firstName")}/></div><div><Label>Last Name</Label><Inp value={form.lastName} onChange={set("lastName")}/></div></div>
        <div><Label>Email</Label><Inp value={form.email} onChange={set("email")} type="email"/></div>
        <div><Label>School</Label><Inp value={form.school} onChange={set("school")}/></div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
          <div><Label>Country</Label><Sel value={form.country} onChange={set("country")}><option>Canada</option><option>USA</option><option>UK</option><option>Australia</option><option>Other</option></Sel></div>
          <div><Label>Province</Label><Inp value={form.province} onChange={set("province")}/></div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}><div><Label>Grade</Label><Inp value={form.grade} onChange={set("grade")} placeholder="12"/></div><div><Label>Grad Year</Label><Inp value={form.graduationYear} onChange={set("graduationYear")} placeholder="2026"/></div></div>
        <div style={{marginTop:4}}><Label>Account Type</Label><div style={{fontSize:12,padding:"8px 12px",background:"#080c14",border:"1px solid #1e2d45",borderRadius:8,color:"#a78bfa",textTransform:"capitalize"}}>{profile?.role||"student"}</div></div>
        <Btn onClick={save} style={{width:"100%",marginTop:6,padding:10}}>{saved?"Saved! ✓":"Save Changes"}</Btn>
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════
// 🏠 MAIN APP
// ══════════════════════════════════════════════════════════════════
export default function Schoolify() {
  const [token,setToken]=useState(null);
  const [profile,setProfile]=useState(null);
  const [years,setYears]=useState(SEED);
  const [activeYear,setActiveYear]=useState("2025-2026");
  const [selectedId,setSelectedId]=useState(101);
  const [tab,setTab]=useState("dashboard");
  const [targetGrade,setTargetGrade]=useState(85);
  const [showAddYear,setShowAddYear]=useState(false);
  const [showProfile,setShowProfile]=useState(false);
  const [gamification,setGamification]=useState({xp:120,streak:3,quizzes:0,flashcards:0,perfect:0,aGrades:2,tools:0,level:1,unlocked:["a1","a4","a8"],log:[{action:"Streak bonus",xp:20,time:"Today"},{action:"Achievement: On Fire",xp:60,time:"3 days ago"},{action:"Grade entered",xp:10,time:"4 days ago"}]});

  const onAuth=(t,p)=>{setToken(t);setProfile(p);};
  const logout=()=>{setToken(null);setProfile(null);};

  const allCourses=useMemo(()=>Object.values(years).flatMap(y=>y.courses),[years]);
  const yearCourses=useMemo(()=>years[activeYear]?.courses||[],[years,activeYear]);
  const findYK=useCallback(id=>Object.keys(years).find(k=>years[k].courses.some(c=>c.id===id)),[years]);

  const enrich=useCallback(c=>{
    const avg=calcWA(c.assignments);
    const gw=c.assignments.filter(a=>a.grade!=="").reduce((s,a)=>s+Number(a.weight),0);
    const tw=c.assignments.reduce((s,a)=>s+Number(a.weight),0);
    const rw=tw-gw;
    return{...c,avg,gw,tw,rw,required:avg!=null?calcReq(avg,gw,targetGrade,rw):null};
  },[targetGrade]);

  const enrichedYear=useMemo(()=>yearCourses.map(enrich),[yearCourses,enrich]);
  const enrichedAll=useMemo(()=>allCourses.map(enrich),[allCourses,enrich]);

  const ys=useMemo(()=>{
    const v=enrichedYear.filter(c=>c.avg!=null);
    const g=v.length?(v.reduce((s,c)=>s+gpa4(c.avg),0)/v.length).toFixed(2):null;
    const t6=[...v].sort((a,b)=>b.avg-a.avg).slice(0,6);
    return{gpa:g,top6:t6.length?(t6.reduce((s,c)=>s+c.avg,0)/t6.length).toFixed(1):null};
  },[enrichedYear]);

  const onXpGain=useCallback((amount,action)=>{
    setGamification(prev=>{
      const nxp=prev.xp+amount;
      const nl=getLvl(nxp).lvl;
      const ns={...prev,xp:nxp,level:nl,log:[{action,xp:amount,time:"Just now"},...prev.log].slice(0,20),
        quizzes:action.toLowerCase().includes("quiz")?prev.quizzes+1:prev.quizzes,
        flashcards:action.toLowerCase().includes("flash")?prev.flashcards+1:prev.flashcards,
        tools:prev.tools+1,
        perfect:action.includes("Perfect")?prev.perfect+1:prev.perfect,
      };
      const nu=ACHIEVEMENTS.filter(a=>!prev.unlocked.includes(a.id)&&a.check(ns)).map(a=>a.id);
      return{...ns,unlocked:[...prev.unlocked,...nu]};
    });
  },[]);

  // Mutations
  const updateGrade=(cid,yk,aid,val)=>setYears(p=>({...p,[yk]:{...p[yk],courses:p[yk].courses.map(c=>c.id!==cid?c:{...c,assignments:c.assignments.map(a=>a.id!==aid?a:{...a,grade:val})})}}));
  const addAssignment=(na)=>{
    const yk=findYK(selectedId);if(!yk||!na.name||!na.weight)return;
    setYears(p=>({...p,[yk]:{...p[yk],courses:p[yk].courses.map(c=>c.id!==selectedId?c:{...c,assignments:[...c.assignments,{...na,id:Date.now(),grade:na.grade||""}]})}}));
  };
  const delAssignment=(aid)=>{const yk=findYK(selectedId);if(!yk)return;setYears(p=>({...p,[yk]:{...p[yk],courses:p[yk].courses.map(c=>c.id!==selectedId?c:{...c,assignments:c.assignments.filter(a=>a.id!==aid)})}}));};
  const addCourse=(nc)=>{
    if(!nc.name)return;
    setYears(p=>({...p,[activeYear]:{...p[activeYear],courses:[...p[activeYear].courses,{id:Date.now(),name:nc.name,code:nc.code,color:PAL[p[activeYear].courses.length%PAL.length],assignments:[]}]}}));
  };
  const addYear=(key,label)=>{setYears(p=>({...p,[key]:{label,current:false,courses:[]}}));setShowAddYear(false);setActiveYear(key);};
  const delYear=(key)=>{if(Object.keys(years).length<=1)return;setYears(p=>{const n={...p};delete n[key];return n;});if(activeYear===key)setActiveYear(Object.keys(years).find(k=>k!==key));};

  if(!token) return <AuthScreen onAuth={onAuth}/>;

  const TABS=[
    {id:"dashboard",icon:"dash",label:"Dashboard"},
    {id:"optimizer",icon:"opt",label:"Grades"},
    {id:"gpa",icon:"gpa",label:"GPA"},
    {id:"university",icon:"uni",label:"University"},
    {id:"ai",icon:"ai",label:"Study AI"},
    {id:"battle",icon:"fire",label:"Battlepass"},
    {id:"resume",icon:"brief",label:"Resume"},
    {id:"competitions",icon:"medal",label:"Competitions"},
    {id:"career",icon:"compass",label:"Career"},
  ];

  const lvlInfo=getLvl(gamification.xp);

  return(
    <div style={{fontFamily:"'Sora','DM Sans',sans-serif",background:"#080c14",minHeight:"100vh",color:"#e2e8f0",display:"flex"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700;800;900&family=DM+Mono:wght@400;500&display=swap');
        *{box-sizing:border-box} ::-webkit-scrollbar{width:4px} ::-webkit-scrollbar-track{background:#080c14} ::-webkit-scrollbar-thumb{background:#1e2d45;border-radius:2px}
        input,select,textarea{outline:none} input::placeholder,textarea::placeholder{color:#334155}
        @keyframes fu{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}} .fu{animation:fu .25s ease}
        @keyframes spin{to{transform:rotate(360deg)}}
      `}</style>

      {showAddYear&&<AddYearModal existing={Object.keys(years)} onAdd={addYear} onClose={()=>setShowAddYear(false)}/>}
      {showProfile&&<ProfilePanel profile={profile} onUpdate={setProfile} onClose={()=>setShowProfile(false)}/>}

      {/* ── SIDEBAR ── */}
      <div style={{width:196,background:"#0a1018",borderRight:"1px solid #0f1e30",display:"flex",flexDirection:"column",position:"sticky",top:0,height:"100vh",flexShrink:0}}>
        {/* Logo */}
        <div style={{padding:"18px 16px 14px",borderBottom:"1px solid #0a1525"}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <div style={{width:30,height:30,background:"linear-gradient(135deg,#3b82f6,#6366f1)",borderRadius:8,display:"flex",alignItems:"center",justifyContent:"center",fontWeight:900,fontSize:14}}>S</div>
            <span style={{fontWeight:900,fontSize:16,letterSpacing:"-0.5px",background:"linear-gradient(135deg,#fff,#94a3b8)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent"}}>Schoolify</span>
          </div>
        </div>

        {/* Year picker */}
        <div style={{padding:"10px 12px",borderBottom:"1px solid #0a1525"}}>
          <div style={{fontSize:8,color:"#334155",textTransform:"uppercase",letterSpacing:1,marginBottom:5}}>Academic Year</div>
          {Object.entries(years).sort(([a],[b])=>b.localeCompare(a)).map(([k,y])=>(
            <div key={k} style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:2}}>
              <button onClick={()=>setActiveYear(k)} style={{flex:1,textAlign:"left",padding:"4px 7px",borderRadius:6,border:`1px solid ${activeYear===k?"#3b82f640":"transparent"}`,background:activeYear===k?"rgba(59,130,246,0.1)":"transparent",color:activeYear===k?"#60a5fa":"#475569",fontSize:11,fontFamily:"inherit",fontWeight:activeYear===k?700:400,cursor:"pointer",display:"flex",alignItems:"center",gap:5}}>
                {y.label}{y.current&&<span style={{fontSize:7,background:"#166534",color:"#4ade80",padding:"1px 4px",borderRadius:99}}>NOW</span>}
              </button>
              {!y.current&&<button onClick={()=>delYear(k)} style={{background:"none",border:"none",color:"#1e2d45",fontSize:9,cursor:"pointer",padding:"2px 4px"}}>✕</button>}
            </div>
          ))}
          <button onClick={()=>setShowAddYear(true)} style={{width:"100%",marginTop:4,padding:"3px 7px",borderRadius:6,border:"1px dashed #1e2d45",background:"transparent",color:"#334155",fontSize:10,fontFamily:"inherit",cursor:"pointer",display:"flex",alignItems:"center",gap:4}}><Ic n="plus" s={9}/> Add Year</button>
        </div>

        {/* Nav */}
        <nav style={{flex:1,padding:"8px 8px",overflowY:"auto"}}>
          {TABS.map(t=>(
            <button key={t.id} onClick={()=>setTab(t.id)} style={{width:"100%",display:"flex",alignItems:"center",gap:8,padding:"7px 9px",borderRadius:8,border:"none",cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:tab===t.id?700:500,marginBottom:1,
              background:tab===t.id?"rgba(59,130,246,0.12)":"transparent",
              color:tab===t.id?"#60a5fa":"#64748b",
              borderLeft:tab===t.id?"2px solid #3b82f6":"2px solid transparent",
              transition:"all .12s"}}>
              <Ic n={t.icon} s={13}/> {t.label}
            </button>
          ))}
        </nav>

        {/* XP bar + user */}
        <div style={{padding:"10px 12px",borderTop:"1px solid #0a1525"}}>
          <div style={{marginBottom:8}}>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:9,color:"#334155",marginBottom:3}}><span>Lv.{lvlInfo.lvl} {lvlInfo.title}</span><span style={{color:"#fbbf24"}}>{gamification.xp}xp</span></div>
            <div style={{height:3,background:"#0f1e30",borderRadius:99}}><div style={{height:"100%",width:lvlInfo.progress+"%",background:lvlInfo.c,borderRadius:99,transition:"width .5s"}}/></div>
          </div>
          <div onClick={()=>setShowProfile(true)} style={{display:"flex",alignItems:"center",gap:8,cursor:"pointer",padding:"6px 7px",borderRadius:8,transition:"background .12s"}} onMouseEnter={e=>e.currentTarget.style.background="rgba(255,255,255,0.03)"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
            <div style={{width:28,height:28,borderRadius:99,background:"linear-gradient(135deg,#1e2d45,#0f1e30)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,color:"#94a3b8",flexShrink:0,border:"1px solid #1e2d45"}}>{profile?.firstName?.[0]?.toUpperCase()||"?"}</div>
            <div style={{flex:1,minWidth:0}}><div style={{fontSize:11,fontWeight:600,color:"#e2e8f0",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{profile?.firstName} {profile?.lastName}</div><div style={{fontSize:9,color:"#475569",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{profile?.school||"No school"}</div></div>
            <button onClick={e=>{e.stopPropagation();logout();}} style={{background:"none",border:"none",color:"#334155",padding:2,cursor:"pointer",display:"flex",flexShrink:0}}><Ic n="logout" s={12}/></button>
          </div>
        </div>
      </div>

      {/* ── MAIN CONTENT ── */}
      <div style={{flex:1,overflowY:"auto",padding:"24px 28px",minWidth:0}}>

        {/* GPA header strip */}
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
          <div style={{fontSize:10,color:"#334155",display:"flex",gap:16}}>
            {ys.gpa&&<span>GPA <b style={{color:"#60a5fa",fontFamily:"'DM Mono',monospace"}}>{ys.gpa}</b></span>}
            {ys.top6&&<span>Top 6 <b style={{color:"#a78bfa",fontFamily:"'DM Mono',monospace"}}>{ys.top6}%</b></span>}
          </div>
          <div style={{fontSize:10,color:"#334155"}}>{years[activeYear]?.label}</div>
        </div>

        <div className="fu">
          {tab==="dashboard"&&<DashboardTab enrichedYear={enrichedYear} years={years} activeYear={activeYear} ys={ys} profile={profile} setTab={setTab} setSelectedId={setSelectedId}/>}
          {tab==="optimizer"&&<OptimizerTab years={years} activeYear={activeYear} enrichedYear={enrichedYear} targetGrade={targetGrade} setTargetGrade={setTargetGrade} selectedId={selectedId} setSelectedId={setSelectedId} updateGrade={updateGrade} addAssignment={addAssignment} delAssignment={delAssignment} addCourse={addCourse} findYK={findYK}/>}
          {tab==="gpa"&&(
            <div>
              <h2 style={{fontSize:20,fontWeight:800,marginBottom:4}}>GPA Calculator</h2>
              <p style={{color:"#475569",fontSize:13,marginBottom:16}}>4.0 scale + Top 6 · {years[activeYear]?.label}</p>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                <C p={18}><div style={{fontSize:12,fontWeight:700,marginBottom:12}}>Course Breakdown</div>
                  {enrichedYear.map(c=>{const g=c.avg!=null?lg(c.avg):null;return(
                    <div key={c.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 12px",background:"#080c14",borderRadius:9,marginBottom:6,borderLeft:`3px solid ${c.color}`}}>
                      <div><div style={{fontSize:12,fontWeight:600}}>{c.name}</div><div style={{fontSize:9,color:"#475569",fontFamily:"'DM Mono',monospace"}}>{c.code}</div></div>
                      <div style={{display:"flex",gap:12}}>
                        {[{l:"Avg",v:c.avg!=null?c.avg.toFixed(1)+"%":"—",col:g?.c||"#475569"},{l:"Letter",v:g?.l||"—",col:g?.c||"#475569"},{l:"GPA",v:c.avg!=null?gpa4(c.avg).toFixed(1):"—",col:"#60a5fa"}].map((s,i)=><div key={i} style={{textAlign:"right"}}><div style={{fontSize:8,color:"#475569"}}>{s.l}</div><div style={{fontSize:14,fontWeight:700,color:s.col,fontFamily:"'DM Mono',monospace"}}>{s.v}</div></div>)}
                      </div>
                    </div>
                  );})}
                </C>
                <div style={{display:"flex",flexDirection:"column",gap:12}}>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                    {[{l:"Cumulative GPA",v:ys.gpa||"—",c:"#60a5fa"},{l:"Top 6 Average",v:ys.top6?ys.top6+"%":"—",c:"#a78bfa"}].map((s,i)=><C key={i} p={16}><Label>{s.l}</Label><div style={{fontSize:36,fontWeight:900,color:s.c,fontFamily:"'DM Mono',monospace",letterSpacing:"-2px",lineHeight:1}}>{s.v}</div></C>)}
                  </div>
                  <C p={14}><div style={{fontSize:10,color:"#475569",marginBottom:10,textTransform:"uppercase",letterSpacing:.8}}>Ontario Grade Scale</div>
                    <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:4}}>
                      {[["A+","90","4.0"],["A","85","3.9"],["A-","80","3.7"],["B+","77","3.3"],["B","73","3.0"],["B-","70","2.7"],["C+","67","2.3"],["C","63","2.0"]].map(([l,r,g])=><div key={l} style={{background:"#080c14",borderRadius:6,padding:"6px",textAlign:"center"}}><div style={{fontSize:11,fontWeight:700,color:lg(parseInt(r)).c,fontFamily:"'DM Mono',monospace"}}>{l}</div><div style={{fontSize:8,color:"#334155",marginTop:1}}>{r}%</div><div style={{fontSize:8,color:"#475569",fontFamily:"'DM Mono',monospace"}}>{g}</div></div>)}
                    </div>
                  </C>
                </div>
              </div>
            </div>
          )}
          {tab==="university"&&<UniTab enrichedAll={enrichedAll} yearCourses={yearCourses} ys={ys}/>}
          {tab==="ai"&&<AIStudyTab yearCourses={yearCourses} enrichedYear={enrichedYear} onXpGain={onXpGain}/>}
          {tab==="battle"&&<BattlepassTab gami={gamification} profile={profile}/>}
          {tab==="resume"&&<ResumeTab profile={profile} enrichedYear={enrichedYear} ys={ys}/>}
          {tab==="competitions"&&<CompTab/>}
          {tab==="career"&&<CareerTab enrichedYear={enrichedYear}/>}
        </div>
      </div>
    </div>
  );
}
