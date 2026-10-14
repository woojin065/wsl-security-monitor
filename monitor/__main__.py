import argparse
from . import state
from .scanner import scan
from .server import serve


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['serve', 'scan', 'scheduled', 'init'])
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    if args.action == 'serve':
        serve(args.port)
    elif args.action == 'init':
        state.config()
    elif args.action == 'scan':
        result = scan()
        print(f'점검 완료: {result["id"]}, 발견 {len(result["findings"])}건')
    elif state.due(state.config(), state.now().date()):
        scan()

if __name__ == '__main__':
    main()
