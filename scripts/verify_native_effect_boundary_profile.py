#!/usr/bin/env python3
import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / 'testdata/governed-action/native-destination-fence/profile-v1.json'

REQUIRED_OBLIGATIONS = {
    'exact_target_identity',
    'exact_effect_attempt_binding',
    'current_owner_identity',
    'current_monotonic_generation',
    'executable_custody_phase',
    'exact_pre_effect_state',
    'current_authority_binding',
    'atomic_check_and_effect',
    'single_effect_cardinality',
    'exact_post_effect_observation',
}

PG_REQUIRED_CHECKS = {
    'exact effect_id and attempt_id',
    'exact owner identity',
    'exact monotonic generation',
    'CROSSING phase',
    'exact pre-effect target revision and digest',
    'active exact admission binding',
}

K8S_REQUIRED_CHECKS = {
    'exact effect_id and attempt_id',
    'exact owner identity',
    'exact monotonic generation',
    'CROSSING custody phase',
    'exact target UID',
    'exact semantic revision and digest',
    'active exact admission binding',
    'resourceVersion CAS on the same destination object',
}


def load_json(path: Path):
    with path.open('r', encoding='utf-8') as handle:
        return json.load(handle)


def git_blob(path: Path) -> str:
    rel = path.relative_to(ROOT)
    return subprocess.check_output(
        ['git', 'hash-object', str(rel)],
        cwd=ROOT,
        text=True,
    ).strip()


def require(condition: bool, message: str):
    if not condition:
        raise ValueError(message)


def verify(profile_path: Path = DEFAULT_PROFILE):
    profile = load_json(profile_path)
    require(profile.get('schema_version') == 'aegis.native-effect-boundary-profile/v1', 'unexpected profile schema')
    require(profile.get('status') == 'experimental-bounded-generalization', 'unexpected profile status')
    require(profile.get('frozen_kernel_contract_changed') is False, 'profile must not claim a frozen-kernel change')
    require(set(profile.get('obligations', [])) == REQUIRED_OBLIGATIONS, 'native obligation set changed')

    realizations = {item['id']: item for item in profile.get('realizations', [])}
    require(set(realizations) == {
        'postgresql-v1',
        'kubernetes-single-object-v1',
        'kubernetes-split-lease-counterexample-v1',
    }, 'unexpected realization set')
    require(realizations['postgresql-v1']['result'] == 'SURVIVES_V1', 'PostgreSQL positive profile must survive')
    require(realizations['kubernetes-single-object-v1']['result'] == 'SURVIVES_V1', 'Kubernetes single-object profile must survive')
    require(realizations['kubernetes-split-lease-counterexample-v1']['result'] == 'INSUFFICIENT', 'split Lease profile must remain a counterexample')

    loaded = {}
    for realization in realizations.values():
        path = ROOT / realization['registration_path']
        require(path.exists(), f'missing registration: {path}')
        actual_blob = git_blob(path)
        require(actual_blob == realization['registration_blob'], f'registration blob drift: {path}')
        loaded[realization['id']] = load_json(path)

    pg = loaded['postgresql-v1']
    k8s = loaded['kubernetes-single-object-v1']

    pins = profile['proof_runtime_pins']
    for name, registration in [('PostgreSQL', pg), ('Kubernetes', k8s)]:
        require(registration['pins']['runtime_blob'] == pins['runtime_blob'], f'{name} runtime proof pin diverged')
        require(registration['pins']['fenced_runtime_blob'] == pins['fenced_runtime_blob'], f'{name} fenced-runtime proof pin diverged')

    require(pg['substrate']['kind'] == 'PostgreSQL', 'PostgreSQL substrate kind changed')
    require('transaction' in pg['substrate']['linearization'].lower(), 'PostgreSQL proof no longer identifies a transaction boundary')
    require(PG_REQUIRED_CHECKS.issubset(set(pg.get('native_boundary_checks', []))), 'PostgreSQL native checks lost a required obligation')
    require({case['id'] for case in pg.get('falsification_cases', [])} == {'NF-PG-01','NF-PG-02','NF-PG-03','NF-PG-04'}, 'PostgreSQL falsification corpus changed')

    require(k8s['substrate']['kind'] == 'Kubernetes API', 'Kubernetes substrate kind changed')
    require('resourceVersion' in k8s['substrate']['linearization'], 'Kubernetes proof no longer identifies resourceVersion CAS')
    require(K8S_REQUIRED_CHECKS.issubset(set(k8s.get('positive_profile_checks', []))), 'Kubernetes native checks lost a required obligation')
    require({case['id'] for case in k8s.get('falsification_cases', [])} == {'NF-K8S-01','NF-K8S-02','NF-K8S-03','NF-K8S-04','NF-K8S-05'}, 'Kubernetes falsification corpus changed')
    require(k8s['conclusion_rule']['split_object_lease_profile'] == 'INSUFFICIENT', 'split-object Kubernetes counterexample was weakened')
    require(k8s['conclusion_rule']['co_located_single_object_profile'] == 'SURVIVES_V1', 'Kubernetes positive profile lost SURVIVES_V1')

    conclusion = profile.get('conclusion', {})
    require(conclusion.get('classification') == 'BOUNDED_GENERALIZATION_EVIDENCE', 'generalization classification changed')
    non_claims = set(conclusion.get('non_claims', []))
    require('not universal provider support' in non_claims, 'universal-provider non-claim missing')
    require('not distributed consensus' in non_claims, 'consensus non-claim missing')
    require('not a new semantic primitive' in non_claims, 'semantic-primitive non-claim missing')

    return {
        'schema_version': profile['schema_version'],
        'classification': conclusion['classification'],
        'positive_realizations': ['postgresql-v1', 'kubernetes-single-object-v1'],
        'negative_realizations': ['kubernetes-split-lease-counterexample-v1'],
        'obligation_count': len(REQUIRED_OBLIGATIONS),
        'proof_runtime_blob': pins['runtime_blob'],
        'proof_fenced_runtime_blob': pins['fenced_runtime_blob'],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', type=Path, default=DEFAULT_PROFILE)
    args = parser.parse_args()
    result = verify(args.profile.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
