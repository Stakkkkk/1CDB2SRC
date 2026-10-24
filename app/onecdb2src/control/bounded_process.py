"""OS dispatcher. Import only the selected process supervisor at invocation."""
import os

def run(argv,stdout_path,stderr_path,receipt_path,seconds,stdout_cap,stderr_cap,rss_cap=1073741824,env=None,*,cancel_event=None):
    if os.name=='nt':
        from .bounded_windows import run as backend
    elif os.name=='posix':
        from .bounded_posix import run as backend
    else:
        raise RuntimeError('Unsupported process supervisor OS')
    if cancel_event is None:
        return backend(argv,stdout_path,stderr_path,receipt_path,seconds,stdout_cap,stderr_cap,rss_cap,env)
    return backend(argv,stdout_path,stderr_path,receipt_path,seconds,stdout_cap,stderr_cap,rss_cap,env,cancel_event=cancel_event)
