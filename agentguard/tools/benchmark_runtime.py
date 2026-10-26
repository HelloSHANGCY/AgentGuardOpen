#!/usr/bin/env python3
"""Compare a committed reference and the working tree in isolated fixture replays.

    python3 tools/benchmark_runtime.py --reference HEAD --out /tmp/runtime-comparison.json

The reference is a Git commit, not the previous uncommitted working tree. No model
services or live range are used. No Git checkout or model activation is performed.
"""

import argparse
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def run(reference):
    revision = subprocess.check_output(['git', 'rev-parse', '--verify', reference + '^{commit}'],
                                       cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory(prefix='ag-opt-reference-') as directory:
        scratch = pathlib.Path(directory)
        archive = subprocess.check_output(['git', 'archive', revision, 'agentguard/agentguard', 'agentguard/tools'],
                                          cwd=ROOT)
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(scratch, filter='data')
        summaries = {}
        for name, source in [('HEAD参考', scratch), ('当前工作区', ROOT)]:
            output = scratch / ('reference.json' if source == scratch else 'current.json')
            env = {key: value for key, value in os.environ.items() if not key.startswith('AG_')}
            env.update(AG_INTENT_LLM_KEY='', AG_BEHAVIOR_DIR='', AG_DATA_DIR='', AG_AGENT_DEVICE_DIR='',
                       AG_EVAL_DB=str(scratch / 'evaluation.db'), AG_STATIC_DB=str(scratch / 'static.db'))
            subprocess.run([sys.executable, str(source / 'agentguard/tools/ablation.py'), '--json', str(output)],
                           cwd=source, env=env, text=True, capture_output=True, check=True)
            summaries[name] = json.loads(output.read_text())['summary']
    return {'reference_revision': revision,
            'comparison': 'committed reference versus current working tree, including pre-existing edits',
            'network_models': False, 'full_range_verified': False, 'summary': summaries}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', default='HEAD')
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    report = run(args.reference)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    for name, summary in report['summary'].items():
        item = summary['全部开启']
        print(f"{name}: {item['tp']}/{item['malicious']} detected; {item['fp']}/{item['benign']} benign triggered; "
              f"engine p95 {item['engine_p95']:.3f} ms")
    return 0


if __name__ == '__main__':
    sys.exit(main())
