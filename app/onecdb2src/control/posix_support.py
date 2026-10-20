"""Linux /proc identity tokens. Never operate on a reused PID."""
import json
import os
import signal
from pathlib import Path

def process(pid):
    try:text=Path('/proc',str(pid),'stat').read_text()
    except (FileNotFoundError,ProcessLookupError):return None
    fields=text[text.rfind(')')+2:].split()
    if len(fields)<22:raise RuntimeError('Incomplete owned process observation')
    return dict(pid=int(pid),state=fields[0],ppid=int(fields[1]),pgid=int(fields[2]),sid=int(fields[3]),
                start_ticks=int(fields[19]),rss_bytes=max(0,int(fields[21]))*os.sysconf('SC_PAGE_SIZE'))

def same_process(token):
    current=process(token['pid'])
    return current if current and current['start_ticks']==token['start_ticks'] else None

def live(token):
    current=same_process(token)
    return current is not None and current['state'] not in ('Z','X')

def signal_process(token,sig):
    """Pidfd binds the signal across the final PID-reuse race."""
    try:fd=os.pidfd_open(token['pid'],0)
    except ProcessLookupError:return
    try:
        if same_process(token):
            try:signal.pidfd_send_signal(fd,sig)
            except ProcessLookupError:pass
    finally:os.close(fd)

def descendants(root,on_process=None):
    result={};root_token=process(root);pending=[root_token] if root_token else []
    while pending:
        parent_token=pending.pop();pid=parent_token['pid']
        if same_process(parent_token) is None:continue
        try:children=Path('/proc',str(pid),'task',str(pid),'children').read_text().split()
        except (FileNotFoundError,ProcessLookupError):continue
        for child in children:
            child=int(child)
            if child in result:continue
            item=process(child)
            if item and item['ppid']==pid and same_process(parent_token) is not None:
                result[child]=item;pending.append(item)
                # Record identities in the caller BEFORE an observation quota
                # can abort enumeration, so finally still owns what to kill.
                if on_process is not None:on_process(item)
                if len(result)>4096:raise RuntimeError('Owned process observation quota exceeded')
    return result

def write_status(path,value):
    raw=json.dumps(value,separators=(',',':')).encode('utf-8')
    if len(raw)>2097152:raise RuntimeError('Process status quota exceeded')
    temporary=path.with_suffix('.tmp')
    with temporary.open('wb') as stream:stream.write(raw)
    os.replace(temporary,path)

def read_status(path):
    try:
        with path.open('rb') as stream:raw=stream.read(2097153)
    except FileNotFoundError:return None
    if len(raw)>2097152:raise RuntimeError('Process status quota exceeded')
    return json.loads(raw)
