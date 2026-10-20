import datetime,hashlib,json,os,stat
from pathlib import Path

def require(ok,message):
    if not ok: raise ValueError(message)

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def read(path): return json.loads(Path(path).read_text('utf-8-sig'))

def save(path,value):
    p=Path(path)
    with p.open('w',encoding='utf-8') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')

def fact(path):
    p=Path(path)
    with p.open('rb') as f:h=hashlib.file_digest(f,'sha256').hexdigest()
    return {'bytes':p.stat().st_size,'sha256':h}

def regular(path,directory=False):
    p=Path(path);s=p.lstat()
    require(not getattr(s,'st_file_attributes',0)&0x400 and not stat.S_ISLNK(s.st_mode),'Reparse/symlink path forbidden')
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode),'Unexpected file kind')
    if not directory:require(s.st_nlink==1,'Hardlinked input forbidden')
    return s

def safe_output(path):
    p=Path(os.path.abspath(path))
    require(not p.exists(),'Output already exists; choose a new directory')
    for parent in p.parents:
        if parent.exists():regular(parent,True)
    return p
