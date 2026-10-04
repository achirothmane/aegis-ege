#!/usr/bin/env node
'use strict';
const assert=require('node:assert/strict');
const m=require('./chronicle.js');
const p=m.profiles().find(x=>x.id==='open-multiple-mutable');
const atomic={...p,atomic:true};
const begin=job=>({kind:'begin',job}),commit=job=>({kind:'commit',job});
let checks=0;
function check(name,fn) {fn();checks++;}

check('No effect is excluded and has undefined semantic coordinates',()=> {
  assert.deepEqual(m.facts([],p),{committed:false,A:null,C:null,P:null});
  assert.equal(m.decideExact([],p).decision,false);
});
check('Physical cause includes exact attempt AND executor',()=> {
  const otherExecutor=m.play([begin(1),commit(1)],p);
  const otherAttempt=m.play([begin(2),commit(2)],p);
  assert.equal(m.facts(otherExecutor.events,p).C,false);
  assert.equal(m.facts(otherAttempt.events,p).C,false);
  assert.equal(m.facts(m.play([begin(0),commit(0)],p).events,p).C,true);
});
check('Commit authority comes from event position, not present restored grant',()=> {
  const restored=m.play([begin(0),{kind:'revoke',actor:0},commit(0),{kind:'restore',actor:0}],p);
  assert.equal(restored.state.active[0],true);
  assert.equal(m.facts(restored.events,p).A,false);
  const laterRevoke=m.play([begin(0),commit(0),{kind:'revoke',actor:0}],p);
  assert.equal(laterRevoke.state.active[0],false);
  assert.equal(m.facts(laterRevoke.events,p).A,true);
});
check('Atomic commitment rejects revoked authority and old epoch without creating an effect',()=> {
  for(const commands of [[begin(0),{kind:'revoke',actor:0},commit(0)],
    [begin(0),{kind:'rotate'},{kind:'restore',actor:0},commit(0)]]) {
    const r=m.play(commands,atomic);
    assert.equal(r.state.effects.length,0);
    assert.equal(r.events.at(-1).kind,'creation_denied');
    assert.equal(m.facts(r.events,atomic).committed,false);
  }
});
check('Target mutation and restoration do not alter recorded historical ancestry',()=> {
  const a=m.play([begin(0),commit(0),{kind:'mutate'}],p);
  const b=m.play([begin(0),commit(0),{kind:'mutate'},{kind:'target_restore'}],p);
  assert.equal(m.facts(a.events,p).P,false);
  assert.equal(m.facts(b.events,p).P,true);
  assert.deepEqual(m.facts(a.events,p).causeWitness,m.facts(b.events,p).causeWitness);
});
check('Dedup returns actual source and a success claim does not change provenance',()=> {
  const r=m.play([begin(0),begin(3),commit(3),commit(0),
    {kind:'claim',claim:{claimedSource:m.JOBS[0].source,authorized:true,current:true,status:'success'}}],p);
  assert.equal(r.state.effects.length,1);
  assert.equal(r.events[3].kind,'dedup_return');
  assert.equal(r.events[3].actualSource,m.JOBS[3].source);
  assert.equal(m.facts(r.events,p).C,false);
});
check('Lost ack and dedup retry preserve exact physical identity',()=> {
  const r=m.play([begin(0),commit(0),{kind:'lose_ack',job:0},{kind:'retry',job:0}],p);
  assert.equal(r.state.effects.length,1);
  assert.equal(r.events.at(-1).kind,'dedup_return');
  assert.equal(m.facts(r.events,p).C,true);
});
check('Without dedup, unchanged focal facts do not discharge cardinality',()=> {
  const r=m.play([begin(0),commit(0),{kind:'lose_ack',job:0},{kind:'retry',job:0}],p,{dedup:false});
  assert.equal(r.state.effects.length,2);
  assert.equal(m.triple(m.facts(r.events,p)),'111');
  assert.equal(m.decideExact(r.events,p).reason,'cardinality');
});
check('Immutable retained bytes can expire',()=> {
  const profile={...p,lifecycle:'expiring'};
  const r=m.play([begin(0),commit(0),{kind:'expire'}],profile);
  assert.equal(r.state.effects[0].retained,true);
  assert.equal(m.facts(r.events,profile).P,false);
});
check('Erasable immutable record is different from permanent retention',()=> {
  const erasable={...p,lifecycle:'erasable'},permanent={...p,lifecycle:'permanent'};
  const r=m.play([begin(0),commit(0),{kind:'erase'}],erasable);
  assert.equal(m.facts(r.events,erasable).P,false);
  assert.throws(()=>m.play([begin(0),commit(0),{kind:'erase'}],permanent));
  assert.throws(()=>m.play([begin(0),commit(0),{kind:'mutate'}],permanent));
});
check('An old observation is truthful at its own point and differs from selected later truth',()=> {
  const r=m.play([begin(0),commit(0),{kind:'snapshot'},{kind:'mutate'}],p);
  assert.equal(r.state.snapshots[0].predicate,true);
  assert.equal(m.facts(r.events,p,'physical-1',3).P,true);
  assert.equal(m.facts(r.events,p).P,false);
  assert.equal(m.decideExact(r.events,p,{},'physical-1',3).decision,true);
  assert.equal(m.decideExact(r.events,p).decision,false);
});

const results=m.generate();
check('Each discovered corner has a reproducible factual witness and an independent decision',()=> {
  for(const experiment of results.experiments) {
    assert.equal(experiment.finiteStateCount,experiment.noEffectStates+experiment.committedStates);
    assert.equal(experiment.fixedContractConflictCount,0);
    for(const witness of experiment.cornerWitnesses) {
      const f=m.facts(witness.trace,experiment.profile);
      assert.equal(m.triple(f),witness.corner);
      const decision=m.decideExact(witness.trace,experiment.profile).decision;
      // Consistency consequence of the stipulated meanings, not a decision oracle.
      assert.equal(decision,Boolean(f.A&&f.C&&f.P));
      if(experiment.profile.atomic) assert.equal(f.A,true);
      if(experiment.profile.exclusive) assert.equal(f.C,true);
      if(experiment.profile.lifecycle==='permanent') assert.equal(f.P,true);
    }
  }
});
check('All sixteen retained-pair functions are exhaustively checked, including unreachable inputs',()=> {
  for(const experiment of results.experiments) for(const dependency of experiment.dependencies) {
    assert.equal(dependency.functions.length,16);
    assert.equal(dependency.groupedWithoutOmittedCoordinate,true);
    for(const fn of dependency.functions) {
      let survives=true;
      for(const witness of experiment.cornerWitnesses) {
        const i=parseInt(dependency.retained.map(c=>Number(witness.facts[c])).join(''),2);
        if(((fn.mask>>i)&1)!==Number(witness.facts[dependency.omitted])) survives=false;
      }
      assert.equal(fn.survives,survives);
    }
    for(const pair of dependency.separatingPairs) {
      const left=experiment.cornerWitnesses.find(w=>w.corner===pair.left);
      const right=experiment.cornerWitnesses.find(w=>w.corner===pair.right);
      assert.equal(dependency.retained.map(c=>Number(left.facts[c])).join(''),pair.projection);
      assert.equal(dependency.retained.map(c=>Number(right.facts[c])).join(''),pair.projection);
      assert.notEqual(left.facts[dependency.omitted],right.facts[dependency.omitted]);
      assert.equal(dependency.survivingMasks.length,0);
    }
  }
});
check('Equal semantic facts with different decisions are classified contract failures',()=> {
  for(const diagnostic of results.disagreementSearch.diagnosticVariants) {
    assert.equal(diagnostic.corner,'111');
    assert.equal(diagnostic.baselineDecision,true);
    assert.equal(diagnostic.variantDecision,false);
    assert.equal(diagnostic.commonFixedSurroundingContract,false);
    assert.ok(diagnostic.classification);
  }
});
check('Required anti-smuggling proposals have stated expansions and boundaries',()=> {
  assert.equal(results.antiSmuggling.length,6);
  for(const x of results.antiSmuggling) {
    assert.ok(x.primary&&x.expansion&&x.smuggling&&x.boundary);
    assert.ok(x.conditional.length>0);
  }
});
check('Deterministic reconstruction is independent of presentation and producer claims',()=> {
  for(const scenario of results.scenarios) {
    const profile=m.profiles().find(x=>x.lifecycle===scenario.lifecycle&&x.id===scenario.profile)||
      {...p,lifecycle:scenario.lifecycle};
    assert.deepEqual(m.facts(scenario.trace,profile),scenario.facts);
    assert.deepEqual(m.facts([...scenario.trace,{kind:'producer_claim',A:!scenario.facts.A,
      C:!scenario.facts.C,P:!scenario.facts.P}],profile).causeWitness,scenario.facts.causeWitness);
  }
});
process.stdout.write(JSON.stringify({ok:true,checks,profiles:results.experiments.length,
  finiteStates:results.experiments.reduce((n,e)=>n+e.finiteStateCount,0),
  scenarios:results.scenarios.length,retainedPairFunctionTests:results.experiments.length*3*16})+'\n');
