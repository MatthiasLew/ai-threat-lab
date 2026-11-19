"""Existing M4.10-M4.13 fixed sandbox diagnostics and Bandit fixture payload."""


def pinned_script(packages, scan):
    script = """
import json, sys, zlib, os, _socket
assert sys.version_info[:3] == (3, 12, 12)
assert sys.executable == '/usr/local/bin/python3.12'
assert sys.path == ['/usr/local/lib/python312.zip', '/usr/local/lib/python3.12',
                    '/usr/local/lib/python3.12/lib-dynload']
assert zlib.decompress(zlib.compress(b'probe')) == b'probe'
try:
    _socket.socket()
except PermissionError:
    pass
else:
    raise AssertionError('socket creation permitted')
for module in tuple(sys.modules.values()):
    path = getattr(module, '__file__', None)
    assert path is None or path.startswith('/usr/local/lib/python3.12/'), path
try:
    open(sys.argv[1], 'rb')
except FileNotFoundError:
    pass
else:
    raise AssertionError('host canary visible')
try:
    open('/usr/local/bin/python3.12', 'wb')
except OSError as error:
    assert error.errno in (13, 30), error
else:
    raise AssertionError('runtime writable')
with open('/scratch/probe', 'xb') as result:
    result.write(b'probe')
for fd in range(3, int(sys.argv[2])):
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == 9, error
    else:
        raise AssertionError('unexpected inherited descriptor')
print(json.dumps({'version': sys.version, 'paths': sys.path, 'zlib': zlib.__file__}))
"""
    if packages:
        script = script[:script.rindex("print(")] + """
import importlib.metadata
sys.path.append('/packages')
import bandit, yaml, yaml._yaml, stevedore, rich, sarif_om, jschema_to_python
from bandit.core import extension_loader
manager = extension_loader.MANAGER
assert importlib.metadata.version('bandit') == '1.7.8'
assert yaml.__with_libyaml__
plugins = sorted(manager.plugins_mgr.names())
assert 'assert_used' in plugins
assert 'sarif' in manager.formatters_mgr.names()
for extension in manager.plugins_mgr.extensions:
    assert extension.plugin.__module__.startswith('bandit.plugins.')
for path in ('/packages/bandit/__init__.py', '/usr/lib/x86_64-linux-gnu/libc.so.6'):
    try:
        open(path, 'wb')
    except OSError as error:
        assert error.errno in (13, 30), error
    else:
        raise AssertionError('staged file writable')
origins = {}
for name, module in tuple(sys.modules.items()):
    path = getattr(module, '__file__', None)
    if path is not None and name != '__main__':
        origins[name] = path
print(json.dumps({'version': sys.version, 'zlib': zlib.__file__, 'paths': sys.path,
                  'origins': origins, 'plugins': plugins,
                  'meta_path': [finder.__name__ for finder in sys.meta_path]}))
"""
    if scan:
        script = script[:script.rindex("print(")] + """
import ctypes, errno
from bandit.cli.main import main
from bandit.core.config import BanditConfig

# Linux amd64 statfs starts with a signed long filesystem magic.
libc = ctypes.CDLL(None, use_errno=True)
for mount in (b'/', b'/scratch'):
    info = (ctypes.c_long * 32)()
    assert libc.statfs(mount, ctypes.byref(info)) == 0, ctypes.get_errno()
    assert info[0] == 0x01021994, (mount, info[0])
assert os.statvfs('/').f_flag & os.ST_RDONLY
assert not os.statvfs('/scratch').f_flag & os.ST_RDONLY
assert os.statvfs('/scratch').f_blocks * os.statvfs('/scratch').f_frsize <= 1048576
for absent in ('/dev', '/proc', '/sys', '/home'):
    assert not os.path.exists(absent), absent
try:
    open('/input/sample.py', 'wb')
except OSError as error:
    assert error.errno in (errno.EROFS, errno.EACCES)
else:
    raise AssertionError('input writable')
os.chdir('/')
# A marker emitted by the actual Bandit manager lets the failure tests stop
# the scanner after entering its analysis path.
from bandit.core.manager import BanditManager
run_tests = BanditManager.run_tests
def marked_run_tests(self):
    print('M415_BANDIT_ANALYSIS', file=sys.stderr, flush=True)
    return run_tests(self)
BanditManager.run_tests = marked_run_tests
sys.argv = ['bandit', '-q', '-c', '/input/config.yaml', '-f', 'sarif',
            '-o', '/scratch/report.sarif', 'input/sample.py']
try:
    main()
except SystemExit as exit:
    code = exit.code
else:
    raise AssertionError('Bandit returned without an exit status')
path = '/scratch/report.sarif'
if code in (0, 1):
    assert BanditConfig('/input/config.yaml').get_option('tests') == ['B101']
    with open(path, 'rb') as stream:
        report = stream.read(32769)
    assert 0 < len(report) <= 32768
    print(json.dumps({'exit': code, 'report': report.decode('utf-8')}))
else:
    assert not os.path.exists(path) or os.stat(path).st_size == 0
    print(json.dumps({'exit': code, 'report': None}))
"""
    return script
