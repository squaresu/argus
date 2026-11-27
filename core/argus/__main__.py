import sys

if len(sys.argv) > 1 and sys.argv[1] in ('scan', 'watch', 'help', '--help', '-h'):
    from .cli import main
    sys.exit(main(sys.argv[1:]))

from .server import main  # noqa: E402

main()
