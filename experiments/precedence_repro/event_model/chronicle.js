#!/usr/bin/env node
'use strict';
// Specification-only finite event model. Only Node standard-library modules.
const fs = require('node:fs');
const path = require('node:path');

const SCOPE = Object.freeze({subject:'subject-cedar', action:'place-violet',
  target:'target-fir', generation:0, boundary:'boundary-elm'});
const EVALUATED = Object.freeze({attempt:'attempt-kappa', executor:'executor-cobalt'});
const ACTORS = ['executor-cobalt','executor-amber'];
const JOBS = [
  {attempt:'attempt-kappa', executor:'executor-cobalt'},
  {attempt:'attempt-kappa', executor:'executor-amber'},
  {attempt:'attempt-lambda', executor:'executor-cobalt'},
  {attempt:'attempt-lambda', executor:'executor-amber'}
].map((j,i)=>({...j, source:`dispatch-${i}`}));
const PREDICATES = Object.freeze({
  mutable:'At the selected observation, the live target contains violet.',
  erasable:'At the selected observation, the exact event record remains stored.',
  permanent:'At the selected observation, the exact permanently retained event exists.',
  expiring:'At the selected observation, the immutable event exists and its fixed validity deadline has not passed.'
});
const COORDINATES = ['A','C','P'];
function clone(x) { return JSON.parse(JSON.stringify(x)); }
function sameScope(a,b) { return Object.keys(SCOPE).every(k=>a[k]===b[k]); }
function initial() {
  return {epoch:0, active:[true,true], jobs:{}, effects:[], target:null,
    clock:0, snapshots:[], acknowledgements:{}, claims:[]};
}
function eligible(s,job,scope=SCOPE) {
  return sameScope(scope,SCOPE) && s.epoch===scope.generation &&
    job.tokenEpoch===s.epoch && s.active[ACTORS.indexOf(job.executor)];
}
function presentPredicate(s,profile,id='physical-1') {
  const e=s.effects.find(x=>x.id===id);
  if(!e) return undefined;
  if(profile.lifecycle==='mutable') return s.target==='violet';
  if(profile.lifecycle==='expiring') return e.retained && s.clock<e.validUntil;
  return e.retained;
}

// Requests become factual events. A receipt/ack/producer claim is never a cause.
function step(before,command,profile,options={}) {
  const s=clone(before); let event;
  const j=command.job===undefined ? null : JOBS[command.job];
  switch(command.kind) {
    case 'begin': {
      const started={...j,tokenEpoch:0,scope:{...SCOPE}};
      s.jobs[j.source]=started;
      event={kind:'attempt_started',...started}; break;
    }
    case 'revoke': s.active[command.actor]=false;
      event={kind:'authority_revoked',executor:ACTORS[command.actor],epoch:s.epoch}; break;
    case 'restore': s.active[command.actor]=true;
      event={kind:'authority_restored',executor:ACTORS[command.actor],epoch:s.epoch}; break;
    case 'rotate': {
      if(s.epoch!==0) throw Error('The finite model has one irreversible epoch advance.');
      s.epoch=1; s.active=[false,false]; event={kind:'epoch_advanced',epoch:1}; break;
    }
    case 'commit': case 'retry': {
      const source=s.jobs[j.source];
      if(!source) throw Error('A commit must reference an earlier started dispatch.');
      // A dedup return is an observation of the earlier physical effect, not creation.
      if(s.effects.length && options.dedup!==false) {
        event={kind:'dedup_return',requester:j.source,physicalId:s.effects[0].id,
          actualSource:s.effects[0].source};
        s.acknowledgements[j.source]='received-existing'; break;
      }
      if(profile.exclusive && j.source!==JOBS[0].source) {
        event={kind:'creation_denied',source:j.source,reason:'exclusive-attempt-and-executor'}; break;
      }
      if(profile.atomic && !eligible(s,source)) {
        event={kind:'creation_denied',source:j.source,reason:'exact-active-authority-and-epoch'}; break;
      }
      const max=options.maxEffects===undefined?2:options.maxEffects;
      if(s.effects.length>=max) throw Error('Physical creation bound exceeded.');
      const e={id:`physical-${s.effects.length+1}`,source:j.source,scope:{...SCOPE},
        commitEpoch:s.epoch,commitGrantActive:s.active[ACTORS.indexOf(j.executor)],
        commitTime:s.clock,validUntil:s.clock+1,retained:true};
      s.effects.push(e); s.target='violet';
      s.acknowledgements[j.source]='received';
      event={kind:'physical_commit',physicalId:e.id,source:e.source,scope:{...SCOPE},
        commitTime:e.commitTime,validUntil:e.validUntil}; break;
    }
    case 'mutate': {
      if(profile.lifecycle!=='mutable') throw Error('This experiment forbids target mutation.');
      s.target='ochre'; event={kind:'target_changed',value:'ochre'}; break;
    }
    case 'target_restore': {
      if(profile.lifecycle!=='mutable') throw Error('This experiment forbids target restoration.');
      s.target='violet'; event={kind:'target_changed',value:'violet'}; break;
    }
    case 'delete': {
      if(profile.lifecycle!=='mutable') throw Error('This experiment forbids target deletion.');
      s.target=null; event={kind:'target_deleted'}; break;
    }
    case 'erase': {
      if(profile.lifecycle!=='erasable') throw Error('Only the erasable profile permits erasure.');
      const e=s.effects.find(x=>x.id===(command.id||'physical-1'));
      if(!e) throw Error('Cannot erase an uncommitted event.');
      e.retained=false; event={kind:'event_erased',physicalId:e.id}; break;
    }
    case 'expire': {
      if(profile.lifecycle!=='expiring'||!s.effects.length) throw Error('Expiry needs an immutable expiring event.');
      s.clock=Math.max(s.clock,s.effects[0].validUntil);
      event={kind:'clock_advanced',now:s.clock}; break;
    }
    case 'lose_ack': s.acknowledgements[j.source]='lost';
      event={kind:'acknowledgement_lost',source:j.source}; break;
    case 'snapshot': {
      const snapshot={label:command.label||'earlier-view',clock:s.clock,
        predicate:presentPredicate(s,profile),target:s.target};
      s.snapshots.push(snapshot); event={kind:'snapshot_recorded',...snapshot}; break;
    }
    case 'claim': event={kind:'producer_claim',...clone(command.claim)};
      s.claims.push(clone(command.claim)); break;
    default: throw Error(`Unknown event request ${command.kind}`);
  }
  return {state:s,event};
}
function play(commands,profile,options={}) {
  let state=initial(); const events=[];
  for(const command of commands) {
    const result=step(state,command,profile,options);
    state=result.state; events.push(result.event);
  }
  return {state,events};
}

// Semantic interpretation replays factual events, rather than accepting stored answer bits.
function facts(events,profile,physicalId='physical-1',observationPrefix=events.length) {
  let epoch=0,active=[true,true],target=null,clock=0;
  const started=new Map(),physical=new Map();
  for(let index=0;index<observationPrefix;index++) {
    const event=events[index];
    if(event.kind==='attempt_started') started.set(event.source,event);
    if(event.kind==='authority_revoked') active[ACTORS.indexOf(event.executor)]=false;
    if(event.kind==='authority_restored') active[ACTORS.indexOf(event.executor)]=true;
    if(event.kind==='epoch_advanced') {epoch=event.epoch;active=[false,false];}
    if(event.kind==='physical_commit') {
      const source=started.get(event.source);
      if(!source) throw Error('Physical provenance refers to an absent dispatch.');
      physical.set(event.physicalId,{event,source,commitIndex:index,
        authorityEpoch:epoch,grantActive:active[ACTORS.indexOf(source.executor)],retained:true});
      target='violet';
    }
    if(event.kind==='target_changed') target=event.value;
    if(event.kind==='target_deleted') target=null;
    if(event.kind==='event_erased') physical.get(event.physicalId).retained=false;
    if(event.kind==='clock_advanced') clock=event.now;
  }
  const e=physical.get(physicalId);
  if(!e) return {committed:false,A:null,C:null,P:null};
  const A=sameScope(e.event.scope,SCOPE) && e.authorityEpoch===e.event.scope.generation &&
    e.grantActive && e.source.tokenEpoch===e.authorityEpoch;
  const C=e.source.attempt===EVALUATED.attempt && e.source.executor===EVALUATED.executor;
  let P;
  if(profile.lifecycle==='mutable') P=target==='violet';
  else if(profile.lifecycle==='expiring') P=e.retained && clock<e.event.validUntil;
  else P=e.retained;
  return {committed:true,A:Boolean(A),C:Boolean(C),P:Boolean(P),
    authorityWitness:{commitIndex:e.commitIndex,epochAtCommit:e.authorityEpoch,
      grantActiveAtCommit:e.grantActive,tokenEpoch:e.source.tokenEpoch},
    causeWitness:{source:e.event.source,attempt:e.source.attempt,executor:e.source.executor},
    observation:{prefix:observationPrefix,clock,predicateId:profile.lifecycle,target,
      retained:e.retained,validUntil:e.event.validUntil}};
}
function triple(f) {return COORDINATES.map(c=>Number(f[c])).join('');}

const VALID_CONTRACT=Object.freeze({fixedDomain:true,physicalIdentity:true,
  exactlyOnePhysicalCommit:true,evidenceIntegrity:true,trustRoots:true,
  independentClaimSelection:true,currentObserverTruthful:true,freshObservation:true,
  historyContinuity:true});

// Independently structured witness checker. It never reads A, C, P or triple().
// Contracts are checked before the actual commit, provenance and current-predicate witnesses.
function decideExact(events,profile,contract={},physicalId='physical-1',prefix=events.length) {
  const obligations={...VALID_CONTRACT,...contract};
  const failures=Object.keys(obligations).filter(k=>!obligations[k]);
  if(failures.length) return {decision:false,reason:'surrounding-contract',failedObligations:failures};
  const commits=events.slice(0,prefix).filter(e=>e.kind==='physical_commit');
  if(commits.length!==1) return {decision:false,reason:'cardinality',physicalCount:commits.length};
  const commit=commits.find(e=>e.physicalId===physicalId);
  if(!commit || !sameScope(commit.scope,SCOPE)) return {decision:false,reason:'physical-identity-or-fixed-scope'};
  const atCommit=events.indexOf(commit);
  const dispatch=events.slice(0,atCommit).findLast(e=>e.kind==='attempt_started'&&e.source===commit.source);
  if(!dispatch) return {decision:false,reason:'causal-history-incomplete'};
  // Reconstruct the issuing grant's history, independently of semantic interpretation.
  let governingEpoch=0,grantCurrentlyActive=true;
  for(const e of events.slice(0,atCommit)) {
    if(e.kind==='epoch_advanced') {governingEpoch=e.epoch;grantCurrentlyActive=false;}
    if(e.executor===dispatch.executor && e.kind==='authority_revoked') grantCurrentlyActive=false;
    if(e.executor===dispatch.executor && e.kind==='authority_restored') grantCurrentlyActive=true;
  }
  if(governingEpoch!==commit.scope.generation || dispatch.tokenEpoch!==governingEpoch || !grantCurrentlyActive)
    return {decision:false,reason:'commit-authority-witness-fails'};
  if(dispatch.attempt!==EVALUATED.attempt || dispatch.executor!==EVALUATED.executor)
    return {decision:false,reason:'exact-attempt-executor-witness-fails'};
  // Interpret the independently selected predicate using only post-commit lifecycle/clock events.
  let liveValue='violet',recordPresent=true,observedClock=commit.commitTime;
  for(const e of events.slice(atCommit+1,prefix)) {
    if(e.kind==='target_changed') liveValue=e.value;
    if(e.kind==='target_deleted') liveValue=null;
    if(e.kind==='event_erased'&&e.physicalId===physicalId) recordPresent=false;
    if(e.kind==='clock_advanced') observedClock=e.now;
  }
  if(profile.lifecycle==='mutable'&&liveValue!=='violet') return {decision:false,reason:'live-target-predicate-fails'};
  if(profile.lifecycle!=='mutable'&&!recordPresent) return {decision:false,reason:'retention-predicate-fails'};
  if(profile.lifecycle==='expiring'&&observedClock>=commit.validUntil) return {decision:false,reason:'validity-predicate-fails'};
  return {decision:true,reason:'all-independent-witnesses-and-contract-valid'};
}

function profiles() {
  const list=[];
  for(const lifecycle of ['mutable','erasable','permanent','expiring'])
    for(const atomic of [false,true]) for(const exclusive of [false,true]) {
      list.push({id:`${atomic?'atomic':'open'}-${exclusive?'exclusive':'multiple'}-${lifecycle}`,
        lifecycle,atomic,exclusive,predicate:PREDICATES[lifecycle]});
    }
  return list;
}
function stateKey(s) {
  // This is a finite behavioral quotient, not a quotient by A/C/P. Raw commit-era
  // epoch/grant facts are retained so post-commit restoration cannot merge distinct histories.
  return JSON.stringify({epoch:s.epoch,active:s.active,jobs:Object.keys(s.jobs).sort(),
    effects:s.effects,target:s.target,clock:s.clock});
}
function enabled(s,p) {
  const commands=[];
  for(let job=0;job<JOBS.length;job++) if(!s.jobs[JOBS[job].source]) commands.push({kind:'begin',job});
  for(let actor=0;actor<ACTORS.length;actor++)
    commands.push({kind:s.active[actor]?'revoke':'restore',actor});
  if(s.epoch===0) commands.push({kind:'rotate'});
  if(!s.effects.length) for(let job=0;job<JOBS.length;job++) if(s.jobs[JOBS[job].source]) {
    if(p.exclusive&&job!==0) continue;
    if(p.atomic&&!eligible(s,s.jobs[JOBS[job].source])) continue;
    commands.push({kind:'commit',job});
  }
  if(s.effects.length) {
    if(p.lifecycle==='mutable') {
      if(s.target!=='ochre') commands.push({kind:'mutate'});
      if(s.target!=='violet') commands.push({kind:'target_restore'});
      if(s.target!==null) commands.push({kind:'delete'});
    }
    if(p.lifecycle==='erasable'&&s.effects[0].retained) commands.push({kind:'erase'});
    if(p.lifecycle==='expiring'&&s.clock<s.effects[0].validUntil) commands.push({kind:'expire'});
  }
  return commands;
}

function dependencyAnalysis(corners,omitted) {
  const retained=COORDINATES.filter(c=>c!==omitted);
  // Build groups using retained coordinates ONLY; then generate equal-projection
  // pairs within these groups before looking at the omitted coordinate.
  const groups=new Map();
  for(const r of corners) {
    const projection=retained.map(c=>Number(r.facts[c])).join('');
    if(!groups.has(projection)) groups.set(projection,[]);
    groups.get(projection).push(r);
  }
  const projectionPairs=[];
  for(const [projection,members] of [...groups].sort())
    for(let i=0;i<members.length;i++) for(let j=i+1;j<members.length;j++)
      projectionPairs.push({projection,left:members[i],right:members[j]});
  const separators=projectionPairs.filter(p=>p.left.facts[omitted]!==p.right.facts[omitted]);
  const functions=[];
  for(let mask=0;mask<16;mask++) {
    const table=[0,1,2,3].map(i=>(mask>>i)&1);
    const failures=corners.filter(r=> {
      const index=2*Number(r.facts[retained[0]])+Number(r.facts[retained[1]]);
      return table[index]!==Number(r.facts[omitted]);
    });
    functions.push({mask,outputsFor00_01_10_11:table.join(''),survives:failures.length===0,
      rejectedBy:failures.length?failures[0].corner:null});
  }
  return {omitted,retained,groupedWithoutOmittedCoordinate:true,
    projectionGroups:[...groups].sort().map(([projection,rs])=>({projection,corners:rs.map(r=>r.corner)})),
    equalProjectionPairCount:projectionPairs.length,
    separatingPairs:separators.map(p=>({projection:p.projection,left:p.left.corner,right:p.right.corner,
      leftTrace:p.left.trace,rightTrace:p.right.trace})),
    functions,survivingMasks:functions.filter(f=>f.survives).map(f=>f.mask)};
}
function explore(profile) {
  const start=initial(),queue=[{state:start,events:[]}],seen=new Set([stateKey(start)]);
  const cornerMap=new Map(); let committedStates=0,noEffectStates=0,transitions=0,maxMinimalDepth=0;
  const exactByTriple=new Map(); let fixedContractConflictCount=0;
  for(let cursor=0;cursor<queue.length;cursor++) {
    const node=queue[cursor]; maxMinimalDepth=Math.max(maxMinimalDepth,node.events.length);
    const f=facts(node.events,profile);
    if(f.committed) {
      committedStates++; const t=triple(f);
      if(!cornerMap.has(t)) cornerMap.set(t,{corner:t,facts:f,trace:node.events});
      const decision=decideExact(node.events,profile).decision;
      if(exactByTriple.has(t)&&exactByTriple.get(t)!==decision) fixedContractConflictCount++;
      exactByTriple.set(t,decision);
    } else noEffectStates++;
    for(const command of enabled(node.state,profile)) {
      const r=step(node.state,command,profile,{maxEffects:1});transitions++;
      const key=stateKey(r.state);
      if(!seen.has(key)) {seen.add(key);queue.push({state:r.state,events:[...node.events,r.event]});}
    }
  }
  const corners=[...cornerMap.values()].sort((a,b)=>a.corner.localeCompare(b.corner));
  const invariants=Object.fromEntries(COORDINATES.map(c=> {
    const values=[...new Set(corners.map(r=>r.facts[c]))];
    return [c,values.length===1?values[0]:null];
  }));
  return {profile,finiteStateCount:seen.size,committedStates,noEffectStates,transitions,
    maxShortestStateDepth:maxMinimalDepth,reachableCorners:corners.map(x=>x.corner),invariants,
    exactDecisionByCorner:Object.fromEntries([...exactByTriple].sort()),
    fixedContractConflictCount,cornerWitnesses:corners,
    dependencies:COORDINATES.map(c=>dependencyAnalysis(corners,c))};
}

function scenarioSuite() {
  const p=profiles().find(p=>p.id==='open-multiple-mutable');
  const atomic={...p,atomic:true,id:'atomic-multiple-mutable'};
  const erasable={...p,lifecycle:'erasable',predicate:PREDICATES.erasable};
  const expiring={...p,lifecycle:'expiring',predicate:PREDICATES.expiring};
  const permanent={...p,lifecycle:'permanent',predicate:PREDICATES.permanent};
  const scenarios=[];
  function add(id,description,commands,profile=p,options={}) {
    const r=play(commands,profile,options); const f=facts(r.events,profile);
    scenarios.push({id,description,profile:profile.id,lifecycle:profile.lifecycle,
      trace:r.events,physicalCount:r.state.effects.length,facts:f,
      corner:f.committed?triple(f):null,exact:decideExact(r.events,profile),
      producerClaims:r.state.claims,snapshots:r.state.snapshots});
    return r;
  }
  const begin=job=>({kind:'begin',job}),commit=job=>({kind:'commit',job});
  add('same-attempt-other-executor','The attempt name matches; the actual executor differs.',[begin(1),commit(1)]);
  add('same-executor-other-attempt','The executor matches; the actual attempt differs.',[begin(2),commit(2)]);
  add('revoked-before-open-commit','Technical permission commits after governed revocation.',[begin(0),{kind:'revoke',actor:0},commit(0)]);
  add('commit-before-revoke','Historical authority remains valid after later revocation.',[begin(0),commit(0),{kind:'revoke',actor:0}]);
  add('revocation-restoration-before-commit','Restoration restores authority before commitment.',[begin(0),{kind:'revoke',actor:0},{kind:'restore',actor:0},commit(0)]);
  add('restoration-after-invalid-commit','Restoration cannot retroactively authorize the physical effect.',[begin(0),{kind:'revoke',actor:0},commit(0),{kind:'restore',actor:0}]);
  add('old-epoch-open','An initially issued token cannot provide current epoch authority after rotation.',[begin(0),{kind:'rotate'},{kind:'restore',actor:0},commit(0)]);
  add('old-epoch-atomic','The atomically enforcing writer rejects a stale epoch token.',[begin(0),{kind:'rotate'},{kind:'restore',actor:0},commit(0)],atomic);
  add('atomic-revoke-before-commit','Revocation wins the serialization race.',[begin(0),{kind:'revoke',actor:0},commit(0)],atomic);
  add('atomic-commit-before-revoke','Commit wins the serialization race.',[begin(0),commit(0),{kind:'revoke',actor:0}],atomic);
  add('foreign-wins-dedup','Two ready candidates race; foreign physical creation wins and q receives a dedup acknowledgement.',[begin(0),begin(3),commit(3),commit(0),{kind:'claim',claim:{status:'success',claimedSource:JOBS[0].source,physicalId:'physical-1'}}]);
  add('evaluated-wins-dedup','Same ready set, reversed serialized commit order.',[begin(0),begin(3),commit(0),commit(3)]);
  add('lost-ack-retry','Lost acknowledgement and retry do not change the recorded physical cause.',[begin(0),commit(0),{kind:'lose_ack',job:0},{kind:'retry',job:0}]);
  add('foreign-origin-retry','Retry after a lost acknowledgement cannot convert foreign provenance into q provenance.',[begin(0),begin(3),commit(3),commit(0),{kind:'lose_ack',job:0},{kind:'retry',job:0}]);
  add('no-dedup-retry-duplicates','Without deduplication, retry may create a second physical effect; scalar facts about the first survive, cardinality fails.',[begin(0),commit(0),{kind:'lose_ack',job:0},{kind:'retry',job:0}],p,{dedup:false,maxEffects:2});
  add('mutable-change','Cause and commit authority persist while the independently fixed live-value predicate becomes false.',[begin(0),commit(0),{kind:'mutate'}]);
  add('mutable-restore','Restoring the live target can restore P without changing the historical physical cause.',[begin(0),commit(0),{kind:'mutate'},{kind:'target_restore'}]);
  add('mutable-delete','Deletion makes the live-value predicate false while the historical effect remains identified.',[begin(0),commit(0),{kind:'delete'}]);
  add('erasable-record','Erasure changes permanent-bytes existence; immutability of the record content does not provide retention.',[begin(0),commit(0),{kind:'erase'}],erasable);
  add('expiry-with-unchanged-bytes','Fixed deadline passes while exact immutable bytes remain.',[begin(0),commit(0),{kind:'expire'}],expiring);
  add('permanent-authority-change','P remains true in the permanently retained event profile even after authority changes.',[begin(0),commit(0),{kind:'revoke',actor:0},{kind:'rotate'}],permanent);
  const old=add('historical-observation-current-change','An earlier truthful snapshot differs from the independently fixed final observation.',[begin(0),commit(0),{kind:'snapshot',label:'before-mutation'},{kind:'mutate'},{kind:'claim',claim:{presentPredicate:true,basis:'before-mutation'}}]);
  const oldPrefix=old.events.findIndex(e=>e.kind==='snapshot_recorded')+1;
  const s=scenarios.at(-1);s.oldObservation={prefix:oldPrefix,facts:facts(old.events,p,'physical-1',oldPrefix),
    exact:decideExact(old.events,p,{},'physical-1',oldPrefix)};
  add('current-restored-old-false-view','The current predicate is true after restoration, but an earlier snapshot is false.',[begin(0),commit(0),{kind:'mutate'},{kind:'snapshot',label:'during-mutation'},{kind:'target_restore'}]);
  return scenarios;
}

function disagreementSearch(scenarios) {
  const baseline=scenarios.find(x=>x.id==='mutable-restore');
  const p=profiles().find(x=>x.id===baseline.profile);
  const variants=[
    {id:'scope-or-policy-substitution',classification:'fixed-domain violation',contract:{fixedDomain:false},
      explanation:'A submitted claim substitutes a scope/policy for the independently fixed domain; the physical baseline facts are unchanged.'},
    {id:'ambiguous-physical-selection',classification:'identity/cardinality ambiguity',contract:{physicalIdentity:false},
      explanation:'A logical key names multiple possible records instead of the already identified physical event.'},
    {id:'untrusted-proof',classification:'trust',contract:{evidenceIntegrity:false,trustRoots:false},
      explanation:'A producer claims the right answer but the exact physical provenance/authorization evidence is untrusted.'},
    {id:'old-view-presented-as-current',classification:'freshness',contract:{freshObservation:false,currentObserverTruthful:false},
      explanation:'An old snapshot is presented as the independently fixed current observation.'},
    {id:'broken-history',classification:'history',contract:{historyContinuity:false},
      explanation:'The physical baseline is unchanged, but its required complete history/evidence continuity is not available.'},
    {id:'postselected-predicate',classification:'claim-policy dependency',contract:{independentClaimSelection:false},
      explanation:'The submitted predicate is chosen because it passes, rather than independently fixed before evaluation.'}
  ].map(v=>({...v,physicalFacts:baseline.facts,corner:baseline.corner,
    baselineDecision:baseline.exact.decision,variantDecision:decideExact(baseline.trace,p,v.contract).decision,
    rejection:decideExact(baseline.trace,p,v.contract),trace:baseline.trace,
    commonFixedSurroundingContract:false}));
  const duplicate=scenarios.find(x=>x.id==='no-dedup-retry-duplicates');
  variants.push({id:'second-physical-commit',classification:'identity/cardinality ambiguity',physicalFacts:duplicate.facts,
    corner:duplicate.corner,baselineDecision:true,variantDecision:duplicate.exact.decision,
    rejection:duplicate.exact,trace:duplicate.trace,commonFixedSurroundingContract:false,
    explanation:'The same focal physical event retains its A/C/P; a second physical effect violates the independently fixed exactly-one contract.'});
  return {method:'The witness checker inspects surrounding obligations, physical identity/cardinality, commit-era authority, dispatch ancestry, and selected current predicate without reading semantic A/C/P.',
    fixedContractConclusion:'No conflict was found by exhaustive finite-state evaluation with the same fixed surrounding contract. Contract-invalid comparison cases are not an added semantic axis.',
    diagnosticVariants:variants};
}

function antiSmuggling() {
  return [
    {proposal:'authorized causal receipt',primary:'REPRESENTATION COLLAPSE',
      expansion:'A receipt that actually certifies exact commit authority and exact attempt/executor ancestry packages two separately grounded propositions. Adding a current-predicate attestation packages a third.',
      conditional:[{category:'DERIVATION',conditions:'Trusted complete receipt, exact physical/scope binding, authoritative commit-point epoch and revocation history, and exact source tuple.',result:'The receipt can derive A and C.'},
        {category:'DERIVATION',conditions:'The receipt establishes P at issue time, and the chosen predicate is preserved by all allowed transitions through the selected observation.',result:'Then P also follows; preservation is explicit and fails for open mutable, erasable or expiring profiles.'}],
      smuggling:'Calling an authorized-causal-current receipt merely C silently includes A and P in causal origin.',
      boundary:'Signing or retaining a receipt alone does not preserve the live target predicate.',witnesses:['mutable-change','expiry-with-unchanged-bytes']},
    {proposal:'state containing verified origin',primary:'DERIVATION',
      expansion:'Authenticated exact physical provenance linked to the started dispatch can derive C. Matching target bytes or a logical dedup key cannot.',
      conditional:[{category:'REPRESENTATION COLLAPSE',conditions:'The state separately stores authenticated authority-at-commit, source tuple and live-predicate evidence.',result:'One record represents multiple semantic propositions.'},
        {category:'SUBSTRATE DISCHARGE',conditions:'Complete mediation permits only this exact attempt/executor to create the exact initially absent effect.',result:'C is invariant true.'}],
      smuggling:'Redefining the independently selected state predicate to include verified origin imports C into P.',
      boundary:'Provenance must remain attached to the exact historical physical effect through current-state changes.',witnesses:['same-attempt-other-executor','foreign-wins-dedup','mutable-restore']},
    {proposal:'still-current receipt',primary:'DERIVATION',
      expansion:'A current receipt can establish P only under an explicit binding from its fresh authoritative observation to the independently fixed predicate.',
      conditional:[{category:'DERIVATION',conditions:'Receipt initially proves P; every P-breaking transition invalidates its checked revision, and the checked revision/clock is read at the selected observation.',result:'Still-current receipt implies preserved P.'},
        {category:'REPRESENTATION COLLAPSE',conditions:'The receipt also independently attests exact authority and source ancestry.',result:'Its single representation contains A, C and P evidence.'}],
      smuggling:'Defining causal validity to mean current receipt validity inserts P into C; selecting P to equal receipt validity changes the fixed predicate unless independently specified.',
      boundary:'Unexpired receipt bytes do not show that a mutable target remains correct; a truthful earlier snapshot has its own observation time.',witnesses:['historical-observation-current-change','current-restored-old-false-view']},
    {proposal:'unified business-effect record',primary:'REPRESENTATION COLLAPSE',
      expansion:'A common schema may store exact physical identity, scoped authority, source ancestry and current validity; one row does not reduce the number of propositions it represents.',
      conditional:[{category:'SUBSTRATE DISCHARGE',conditions:'Enforced exact-authority admission, exclusive exact attempt/executor creation, or durable permanent retention is separately proved.',result:'Only the corresponding A, C or P obligation is discharged.'}],
      smuggling:'Replacing exact physical cause with logical business-key equality changes C, and aggregating duplicates hides physical identity/cardinality obligations.',
      boundary:'Business key, exact physical effect, evaluated dispatch and current target are different bindings.',witnesses:['foreign-wins-dedup','no-dedup-retry-duplicates']},
    {proposal:'atomic transaction',primary:'SUBSTRATE DISCHARGE',
      expansion:'Atomicity can discharge A when every creation atomically validates exact active scoped authority and current generation/epoch, revocation serializes with commit, and no bypass exists.',
      conditional:[{category:'DERIVATION',conditions:'Transaction establishes P at commit and all permitted later transitions preserve the selected predicate through observation.',result:'P is derived conditionally; atomicity alone only establishes the commit-time state.'},
        {category:'SUBSTRATE DISCHARGE',conditions:'The same trusted mediation additionally restricts the exact creator tuple, or enforces permanent immutable retention.',result:'C or P can separately become invariant.'}],
      smuggling:'Calling any atomic write authorized, or substituting its transaction snapshot for later selected current observation, imports obligations not supplied by atomicity.',
      boundary:'Multiple authorized dispatches remain possible, and later mutable/expiry events remain possible.',witnesses:['atomic-revoke-before-commit','atomic-commit-before-revoke','same-attempt-other-executor','mutable-change']},
    {proposal:'sole-writer store',primary:'SUBSTRATE DISCHARGE',
      expansion:'A sole writer discharges C only if trusted complete mediation proves that it serves solely the one evaluated exact attempt/executor for this initially absent effect. One service may serve many attempts.',
      conditional:[{category:'SUBSTRATE DISCHARGE',conditions:'The sole writer also performs exact atomic authority checks and current epoch validation.',result:'A is invariant true.'},
        {category:'SUBSTRATE DISCHARGE',conditions:'The selected predicate is permanent existence of a durably retained immutable event.',result:'P is invariant true.'}],
      smuggling:'Equating writer identity with evaluated attempt identity silently drops the attempt part of C; equating technical write access with governed authority drops A.',
      boundary:'Same executor serving another attempt defeats causal inference even with a single writer.',witnesses:['same-executor-other-attempt','revoked-before-open-commit']}
  ];
}

const LIMITS=[
  'Finite standard-library software experiment, not an external human laboratory or a proof about every implementation.',
  'Two executor agents of one fixed subject, two attempt IDs, one epoch advance, initial epoch-zero capability tokens, one identified physical effect and one finite target value abstraction.',
  'Core reachability explores all states of a behavioral quotient with at most one physical creation. Repeated authority/target cycles are quotiented by state plus retained raw commit-era facts. Dedicated scenarios cover two physical creations and cardinality failure.',
  'All physical operations are serialized events. Both orders of ready contenders and commit/revocation races are represented; weak-memory behavior, untrusted hardware and low-level partial commits are outside the trusted complete-event abstraction.',
  'Mutable restoration is restoration of the target value, not recreation of the same deleted physical event. An erased immutable record is not recreated under the old physical identity.',
  'Expiry uses two clock regions around a fixed deadline, sufficient for this selected expiring-validity predicate; clocks and evidence timestamps are trusted within the fixed contract.',
  'Producer claims, acknowledgements, dedup replies and old snapshots do not establish ground truth. Contract-invalid diagnostics hold physical semantics fixed and explicitly vary surrounding obligations.',
  'Trusted event records model factual evidence; this is not a cryptographic implementation or a defense against fabricated records.',
  'Predicate IDs, scope, evaluated tuple and selected observation are fixed per experiment; different lifecycle predicates are separate experiments.'
];

function generate() {
  const experiments=profiles().map(explore),scenarios=scenarioSuite();
  return {schema:'cedar-chronicle-v1',semanticInput:'Frozen reproduction specification v1 only',
    runtime:'Node.js standard library',fixedScope:SCOPE,evaluated:EVALUATED,
    candidates:JOBS,predicates:PREDICATES,initialCondition:'No committed effect; both executor grants active in epoch zero.',
    truthTableConvention:'Masks 0..15: bit 0 is output at retained pair 00, bit 1 at 01, bit 2 at 10, bit 3 at 11.',
    experiments,scenarios,disagreementSearch:disagreementSearch(scenarios),antiSmuggling:antiSmuggling(),limits:LIMITS};
}

function report(results) {
  const rows=results.experiments.map(r=>`| ${r.profile.id} | ${r.reachableCorners.join(', ')} | ${COORDINATES.filter(c=>r.invariants[c]!==null).map(c=>c+'='+Number(r.invariants[c])).join(', ')||'none'} | ${r.dependencies.map(d=>d.omitted+': '+(d.survivingMasks.length?d.survivingMasks.join(','):'none')).join('; ')} |`);
  return `# Independent event/history experiment\n\nThis standalone JavaScript model was constructed from the frozen specification only. It starts with no effect. Attempts start with exact attempt/executor dispatch identity; physical commitment references that dispatch. Governed revocation, restoration and epoch events precede or follow commitment. Target, retention and clock events determine an independently fixed observation-time predicate. No transition assigns A/C/P answer bits. No repository, prior implementation, helper, fixture or result corpus was inspected.\n\n## Reproduction\n\nRun \`node checks.js\` for tests. Run \`node chronicle.js --out ./rerun\` to create results and witness files in a chosen directory, or \`node chronicle.js --stdout\` for JSON. The commands use only files in this experiment directory and Node standard libraries.\n\n## Reachability and functions\n\nAll rows were discovered by breadth-first closure of the finite event state graph. A/C/P are interpreted afterward from each shortest retained history. No-effect states have null coordinates and are excluded. Corner order is A,C,P. Invariant coordinates are scoped to the stated restrictions. Functional dependencies are total Boolean functions on a retained pair, with behavior off the reachable retained inputs unconstrained. The numbers below are all surviving truth-table masks from 0 through 15; the full JSON includes all rejected functions and counterexamples.\n\n| Profile | Reachable committed corners | Invariants | Surviving masks for omitted coordinate |\n|---|---|---|---|\n${rows.join('\n')}\n\nProjection groups are built using only the retained coordinates. All pairs inside those groups are formed before testing the omitted coordinate. Equal retained projections with unequal omitted values reject all sixteen functions. Restricted profiles may constrain a coordinate; their surviving functions include every possible completion on unreachable inputs, rather than claiming unique global laws.\n\n## What the event histories establish\n\nThe open mutable, erasable and expiring experiments allow historical authority and exact dispatch ancestry to vary independently of the selected current predicate. Atomic scoped authority checks remove invalid-authority commitment, exclusive trusted exact-tuple creation removes foreign origin, and permanent immutable retention with permanent-existence predicate removes predicate failure. The composed rows above give the resulting domain restrictions without changing the predicate within an experiment.\n\nRestoration after commitment does not retroactively authorize an invalid commit. Revocation after a valid commitment does not falsify historical authority. Same attempt/different executor and same executor/different attempt both fail exact ancestry. A dedup reply returns an existing physical effect, with its existing origin; it does not grant the requesting attempt authorship. The two candidate commit orders yield different origins. Lost acknowledgement and retry retain cause under dedup; a non-dedup retry creates a second physical effect and fails the fixed cardinality contract. An old truthful snapshot may differ from present truth, and selecting a different observation changes the domain.\n\n## EXACT_EFFECT disagreement search\n\nThe decision checker separately validates fixed contract obligations, one exact physical commitment, governing grant history at commit, the dispatch ancestry, and the selected live predicate. It never reads the computed A/C/P fields. Exhaustive checks found ${results.experiments.reduce((n,r)=>n+r.fixedContractConflictCount,0)} equal-A/C/P decision conflicts under the same fixed contract. This agrees with the specification's meaning rather than establishing the conjunction through a preprogrammed cube oracle.\n\nSeven diagnostic cases retain the focal physical semantics while violating fixed-domain selection, physical identity/cardinality, evidence trust, freshness/current-observer truthfulness, history continuity, or independent claim-policy selection. Their different eligibility decisions are surrounding-contract dependencies. They cannot be inserted as a new truth axis without changing the declared domain. A fabricated producer claim is explicitly separate from physical/event truth.\n\n## Anti-smuggling classification\n\n${results.antiSmuggling.map(x=>`**${x.proposal}: ${x.primary}.** ${x.expansion} ${x.conditional.map(c=>c.category+': '+c.conditions+' '+c.result).join(' ')} SEMANTIC SMUGGLING: ${x.smuggling} Boundary: ${x.boundary}`).join('\n\n')}\n\nDERIVATION means a separately proved fact implies another under stated assumptions, including explicit predicate preservation through observation. SUBSTRATE DISCHARGE means an enforcement restriction makes an obligation invariant. REPRESENTATION COLLAPSE combines distinct facts in one representation. SEMANTIC SMUGGLING changes the meanings by inserting authority, cause or present validity into another coordinate. Multiple labels can describe different uses of the same proposal.\n\n## Limits\n\n${results.limits.map(x=>'- '+x).join('\n')}\n`;
}

function writeResults(out) {
  const results=generate(); fs.mkdirSync(out,{recursive:true});
  fs.writeFileSync(path.join(out,'analysis.json'),JSON.stringify(results,null,2)+'\n');
  fs.writeFileSync(path.join(out,'trace-witnesses.json'),JSON.stringify({
    corners:results.experiments.map(r=>({profile:r.profile.id,witnesses:r.cornerWitnesses})),
    projectionSeparators:results.experiments.map(r=>({profile:r.profile.id,
      dependencies:r.dependencies.map(d=>({omitted:d.omitted,retained:d.retained,separatingPairs:d.separatingPairs}))})),
    scenarios:results.scenarios,contractDiagnostics:results.disagreementSearch.diagnosticVariants},null,2)+'\n');
  fs.writeFileSync(path.join(out,'report.md'),report(results));
  return results;
}
if(require.main===module) {
  if(process.argv.includes('--stdout')) process.stdout.write(JSON.stringify(generate(),null,2)+'\n');
  else {
    const at=process.argv.indexOf('--out'),out=at<0?path.join(__dirname,'results'):process.argv[at+1];
    if(!out) throw Error('--out requires a directory');
    const r=writeResults(path.resolve(out));
    process.stdout.write(JSON.stringify({profiles:r.experiments.length,scenarioCount:r.scenarios.length,
      states:r.experiments.reduce((n,x)=>n+x.finiteStateCount,0),output:path.resolve(out)})+'\n');
  }
}
module.exports={SCOPE,EVALUATED,ACTORS,JOBS,PREDICATES,VALID_CONTRACT,initial,eligible,
  step,play,facts,triple,presentPredicate,decideExact,profiles,explore,dependencyAnalysis,
  scenarioSuite,disagreementSearch,antiSmuggling,generate,report,writeResults};
