import json
import os
import subprocess
import sys
import urllib.request

from flask import Blueprint, Response, jsonify, stream_with_context

update_bp = Blueprint('update', __name__, url_prefix='/api/update')

REPO_OWNER = 'flyingsurveyor'
REPO_NAME = 'qrfs'
REPO_BRANCH = 'main'


def _repo_root() -> str:
    # .../repo_root/qrfs/routes/update.py -> repo_root
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _git(*args: str, timeout: int = 5) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ['git', '-C', _repo_root(), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return None


def _local_head() -> str | None:
    result = _git('rev-parse', 'HEAD')
    if result and result.returncode == 0:
        sha = (result.stdout or '').strip()
        return sha or None
    return None


def _is_git_repo() -> bool:
    result = _git('rev-parse', '--is-inside-work-tree')
    if result and result.returncode == 0:
        return (result.stdout or '').strip().lower() == 'true'
    return False


def _short_sha(value: str | None) -> str | None:
    if not value:
        return None
    return value[:7]


def _remote_head() -> str | None:
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/commits/{REPO_BRANCH}'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'qrfs-updater'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        sha = (data.get('sha') or '').strip()
        return sha or None
    except Exception:
        return None


@update_bp.route('/check')
def api_update_check():
    local_full = _local_head()
    remote_full = _remote_head()
    git_repo = _is_git_repo()
    requirements_path = os.path.join(_repo_root(), 'requirements.txt')

    up_to_date = bool(local_full and remote_full and local_full == remote_full)
    update_available = bool(local_full and remote_full and local_full != remote_full)

    return jsonify({
        'repo': f'{REPO_OWNER}/{REPO_NAME}',
        'branch': REPO_BRANCH,
        'git_repo': git_repo,
        'can_self_update': git_repo,
        'local': _short_sha(local_full) or 'unknown',
        'remote': _short_sha(remote_full),
        'up_to_date': up_to_date,
        'update_available': update_available,
        'requirements_present': os.path.isfile(requirements_path),
    })


@update_bp.route('/run')
def api_update_run():
    def generate():
        def emit(line: str, kind: str = 'log'):
            payload = json.dumps({'kind': kind, 'line': line}, ensure_ascii=False)
            return f'data: {payload}\n\n'

        if not _is_git_repo():
            yield emit('This QRFS instance is not running from a git checkout. Self-update is unavailable.', 'error')
            yield emit('DONE', 'done')
            return

        base = _repo_root()
        yield emit('Checking repository...', 'log')

        yield emit('▶ git pull --ff-only', 'log')
        try:
            proc = subprocess.Popen(
                ['git', '-C', base, 'pull', '--ff-only'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    yield emit(line, 'log')
            proc.wait()
            if proc.returncode != 0:
                yield emit(f'git pull failed (exit {proc.returncode}).', 'error')
                yield emit('DONE', 'done')
                return
        except Exception as exc:
            yield emit(f'Git error: {exc}', 'error')
            yield emit('DONE', 'done')
            return

        yield emit('git pull completed.', 'ok')

        req_file = os.path.join(base, 'requirements.txt')
        if os.path.isfile(req_file):
            yield emit('▶ pip install -r requirements.txt', 'log')
            try:
                proc = subprocess.Popen(
                    [
                        sys.executable,
                        '-m',
                        'pip',
                        'install',
                        '--disable-pip-version-check',
                        '-r',
                        req_file,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                assert proc.stdout is not None
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        yield emit(line, 'log')
                proc.wait()
                if proc.returncode != 0:
                    yield emit(f'pip install finished with errors (exit {proc.returncode}).', 'warn')
                else:
                    yield emit('Dependencies updated.', 'ok')
            except Exception as exc:
                yield emit(f'Pip error: {exc}', 'warn')
        else:
            yield emit('requirements.txt not found, skipped.', 'warn')

        yield emit('Update completed. Restart QRFS to load the new code.', 'ok')
        yield emit('DONE', 'done')

    response = Response(stream_with_context(generate()), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response
