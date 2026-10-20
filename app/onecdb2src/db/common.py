import datetime
import hashlib
import json
import re

CHUNK = 1024 * 1024
TABLES = ('config', 'configsave', 'configcas', 'configcassave', 'depotfiles')
FIELDS = ('file_name', 'part_no', 'data_size', 'attributes', 'creation', 'modified')

class CaptureError(ValueError):
    """Safe diagnostic, deliberately excluding driver/server exception text."""

def require(ok, message):
    if not ok:
        raise CaptureError(message)

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')

def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', value), 'Unsupported SQL identifier')
    return value

def metadata(value):
    require(isinstance(value, dict) and set(value) == set(FIELDS), 'Unexpected Config metadata fields')
    name = value['file_name']
    require(isinstance(name, str) and 0 < len(name) <= 255 and not any(c in name for c in '/\\:*?"<>|\x00\r\n') and name not in ('.', '..') and not name.endswith(('.', ' ')), 'Unsafe Config filename')
    for key in ('part_no', 'data_size', 'attributes'):
        require(type(value[key]) is int and value[key] >= 0, 'Invalid Config numeric metadata')
    require(value['attributes'] == 0, 'Unsupported Config Attributes')
    for key in ('creation', 'modified'):
        require(isinstance(value[key], str) and 0 < len(value[key]) <= 128, 'Invalid source date text')
    return value

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
