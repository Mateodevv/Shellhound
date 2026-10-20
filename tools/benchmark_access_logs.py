"""Offline access-index benchmark; all generated evidence is temporary.

python -m tools.benchmark_access_logs --requests 750000 --uri-bytes 4000
"""
import argparse
import json
from pathlib import Path
import tempfile
import time

from server.engines import logindex


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requests', type=int, default=200000)
    parser.add_argument('--uri-bytes', type=int, default=64,
                        help='bytes of harmless padding in each distinct query string')
    parser.add_argument('--clients', type=int, default=50000)
    parser.add_argument('--overview', action='store_true', help='also measure the optional distributions')
    args = parser.parse_args()
    if args.requests < 1 or args.uri_bytes < 0 or not 1 <= args.clients <= 65536:
        parser.error('requests must be positive, URI padding nonnegative and clients 1..65536')
    with tempfile.TemporaryDirectory(prefix='shellhound-scale43-') as directory:
        root = Path(directory)
        source, case = root / 'access.log', root / 'case'
        case.mkdir()
        with source.open('w', encoding='utf-8') as stream:
            for n in range(args.requests):
                client = n % args.clients
                uri = f'/catalog/item-{n}?query=' + 'x' * args.uri_bytes
                stream.write(f'198.18.{client // 256}.{client % 256} - - '
                             f'[01/Jan/2026:00:{n // 60 % 60:02}:{n % 60:02} +0000] '
                             f'"GET {uri} HTTP/1.1" {404 if n % 5 == 0 else 200} 123 "-" "Synthetic43"\n')
        print(json.dumps({'phase': 'input_written', 'bytes': source.stat().st_size,
                          'lines': args.requests}), flush=True)
        started = time.perf_counter()
        stats = logindex.build(case, [str(source)])
        build_seconds = time.perf_counter() - started
        started = time.perf_counter()
        response = logindex.access_search(case, limit=25)
        search_seconds = time.perf_counter() - started
        assert stats['lines'] == response['total'] == args.requests
        assert stats['clients'] == min(args.requests, args.clients)
        assert stats['unparsed'] == stats['skipped'] == 0
        assert response['summary']['client_errors'] == (args.requests + 4) // 5
        overview_seconds = None
        if args.overview:
            started = time.perf_counter()
            overview = logindex.access_overview(case)
            overview_seconds = time.perf_counter() - started
            assert overview['total'] == args.requests
        peak_mib = None
        try:
            import resource
            import sys
            peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            peak_mib = peak / (1024 ** 2 if sys.platform == 'darwin' else 1024)
        except ImportError:
            pass  # Windows still reports timings and exact result checks.
        print(json.dumps({'requests': args.requests, 'input_bytes': source.stat().st_size,
                          'index_bytes': stats['index_size'], 'build_seconds': build_seconds,
                          'search_seconds': search_seconds, 'overview_seconds': overview_seconds,
                          'peak_rss_mib': peak_mib}), flush=True)


if __name__ == '__main__':
    main()
