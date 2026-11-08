"""Runtime model catalogue; provider secrets and endpoints remain server-owned."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from flask import jsonify, request

SETTINGS_PATH = Path('model_settings.json')
_lock = threading.RLock()


def snapshot(base_models, default):
    with _lock:
        if SETTINGS_PATH.exists():
            return json.loads(SETTINGS_PATH.read_text())
        return {'models': copy.deepcopy(base_models), 'default': default}


def public_catalog(data):
    rows = [{
        'name': m.get('name', m.get('key')),
        'label': m.get('readable_name', m.get('label', m.get('name', m.get('key')))),
        'model_id': m.get('params', {}).get('model', ''),
        'enabled': m.get('enabled', True),
    } for m in data['models']]
    result = {'models': rows, 'default': data['default']}
    result['revision'] = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    return result


def resolve(data, selected):
    names = [m.get('name', m.get('key')) for m in data['models'] if m.get('enabled', True)]
    if not names:
        raise ValueError('At least one model must be enabled')
    return selected if selected in names else data['default'] if data['default'] in names else names[0]


def validated_update(current, payload):
    if not isinstance(payload, dict) or set(payload) - {'models', 'default', 'revision'}:
        raise ValueError('Supply models, default and revision only')
    if payload.get('revision') != public_catalog(current)['revision']:
        raise LookupError('Models changed in another session. Reload the list before saving.')
    rows = payload.get('models')
    if not isinstance(rows, list) or not rows or len(rows) > 200:
        raise ValueError('Supply between 1 and 200 models')
    existing = {m.get('name', m.get('key')): m for m in current['models']}
    models, seen, ids = [], set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) - {'name', 'label', 'model_id', 'enabled'}:
            raise ValueError('Invalid model fields')
        name, label, model_id = row.get('name'), row.get('label'), row.get('model_id')
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 120 or type(row.get('enabled')) is not bool:
            raise ValueError('Each model needs a label and an enabled switch')
        if name in existing:
            model = copy.deepcopy(existing[name])
            if model_id != model.get('params', {}).get('model', ''):
                raise ValueError('Add a new entry to use a different model ID')
        else:
            if not isinstance(model_id, str) or len(model_id) > 200 or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.:/+-]+', model_id):
                raise ValueError('Use an OpenRouter model ID such as publisher/model-name')
            name = 'openrouter_custom_' + hashlib.sha256(model_id.encode()).hexdigest()[:16]
            model = {'name': name, 'provider': 'openrouter', 'params': {'model': model_id}}
        if name in seen or (model_id and model_id in ids):
            raise ValueError('Duplicate model entry')
        seen.add(name); ids.add(model_id)
        model.update(readable_name=label.strip(), enabled=row['enabled'])
        models.append(model)
    if set(existing) - seen:
        raise ValueError('Disable existing models instead of removing them')
    default = payload.get('default')
    # A newly added row uses its model ID until the server assigns its stable name.
    for model in models:
        if default == model.get('params', {}).get('model'):
            default = model['name']
    result = {'models': models, 'default': default}
    if default not in [m.get('name', m.get('key')) for m in models if m.get('enabled', True)]:
        raise ValueError('Choose an enabled default model')
    return result


def save(data):
    with tempfile.NamedTemporaryFile('w', dir=SETTINGS_PATH.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(data, stream, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, SETTINGS_PATH)
        finally:
            temporary.unlink(missing_ok=True)


def install(app, load, admin_required, login_required):
    @app.get('/api/models')
    @login_required
    def model_options():
        data = public_catalog(load())
        data['models'] = [m for m in data['models'] if m['enabled']]
        return jsonify(data)

    @app.route('/api/admin/models', methods=['GET', 'PUT'])
    @admin_required
    def admin_models():
        with _lock:
            current = load()
            if request.method == 'PUT':
                try:
                    current = validated_update(current, request.get_json(silent=True))
                except LookupError as error:
                    return jsonify(error=str(error)), 409
                except (ValueError, TypeError) as error:
                    return jsonify(error=str(error)), 400
                save(current)
            return jsonify(public_catalog(current))
