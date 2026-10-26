"""
HTTP layer (Flask, optional: pip install "rulezet-tester[web]").

    GET  /sets?format=                         -> { available, sets: [...] }
    POST /           { format, text, sets }    -> 202 run (samples pending)
    GET  /<run id>                             -> run (poll until status is done | failed)

Mount it wherever you want; rulezet-editor mounts it on /editor-api/test, so the editor's
browser code finds it next to the rest of the editor API.

    app.register_blueprint(create_blueprint(service, owner=lambda: current_user.id), url_prefix='/test')
"""
from flask import Blueprint, Flask, jsonify, request

from .runs import TestError

SAMPLES = __import__('pathlib').Path(__file__).resolve().parents[1] / 'samples'


def create_blueprint(service, owner=None, name='rulezet_tester'):
    """owner(): who is asking (the host's user id): a run is only visible to the one who started
    it. None: no owner check (single-user tool)."""
    bp = Blueprint(name, __name__)
    who = owner or (lambda: None)

    def error(message, status):
        return jsonify({'error': message}), status

    @bp.get('/sets')
    def sets():
        fmt = request.args.get('format', '').strip()
        if fmt not in service.formats():
            return jsonify({'available': False, 'sets': []})
        return jsonify({'available': True, 'sets': service.sets(fmt)})

    @bp.post('/')
    def start():
        payload = request.get_json(silent=True) or {}
        chosen = payload.get('sets')
        if not isinstance(chosen, list):
            return error('No sample set chosen.', 400)
        try:
            run = service.start(str(payload.get('format') or '').strip(), payload.get('text'),
                                [str(s) for s in chosen][:50], owner=who())
        except TestError as e:
            return error(str(e), 400)
        return jsonify(run), 202

    @bp.get('/<string:run_id>')
    def state(run_id):
        run = service.state(run_id, owner=who())
        return jsonify(run) if run else error('Test run not found.', 404)

    return bp


def create_app(samples=(), sandbox='bwrap', prefix='/test'):
    """Standalone test server (no database): the shipped safe sets plus `samples` folders."""
    from .runs import TestService
    from .samples import FolderSampleStore
    from .sandbox import Sandbox
    service = TestService(FolderSampleStore(SAMPLES, *samples), Sandbox(mode=sandbox))
    app = Flask(__name__)
    app.register_blueprint(create_blueprint(service), url_prefix=prefix)
    app.config['TEST_SERVICE'] = service
    return app
