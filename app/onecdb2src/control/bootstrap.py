"""Wait for the parent Job assignment before starting the requested process."""
def require(condition,message):
 if not condition:raise ValueError(message)

import json,subprocess,sys
if sys.stdin.buffer.readline()!=b'GO\n':raise SystemExit(126)
argv=json.loads(sys.argv[1]);require(isinstance(argv,list) and argv and all(isinstance(x,str) for x in argv),'Bounded process invariant failed')
raise SystemExit(subprocess.run(argv,stdin=subprocess.DEVNULL).returncode)
