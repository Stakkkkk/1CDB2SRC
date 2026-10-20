"""Переносимая точка входа SQL → два CF и XML, без платформы 1С."""
import sys
if __name__ == '__main__':
    # Windows redirected streams may otherwise use a legacy code page.
    # Only CLI diagnostics are configured here; input/payload streams stay intact.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    if sys.argv[1:2] == ['--_worker']:
        from onecdb2src.worker import main
        raise SystemExit(main(sys.argv[2:]))
    from onecdb2src.cli import main
    raise SystemExit(main())
