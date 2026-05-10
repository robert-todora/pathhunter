#!/usr/bin/env python3
"""
PathHunter - HTTP path and method enumeration tool

Discovers accessible endpoints by combining wordlists with action lists
and probing each combination across multiple HTTP methods.
"""

import argparse
import sys
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings when --insecure is used
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"


BANNER = rf"""{C.CYAN}
   ___      _   _      _  _              _
  / _ \__ _| |_| |_   | || |_  _ _ _  __| |_ ___ _ _
 |  _/ _` |  _| ' \  | __ | || | ' \/ _|  _/ -_) '_|
 |_| \__,_|\__|_||_| |_||_|\_,_|_||_\__|\__\___|_|
{C.RESET}{C.GRAY}      HTTP path & method enumeration tool{C.RESET}
"""


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def info(msg):
    print(f"{C.BLUE}[*]{C.RESET} {msg}")


def good(msg):
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def warn(msg):
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg):
    print(f"{C.RED}[-]{C.RESET} {msg}", file=sys.stderr)


def status_color(code):
    """Color a status code by its category."""
    if 200 <= code < 300:
        return f"{C.GREEN}{code}{C.RESET}"
    if 300 <= code < 400:
        return f"{C.CYAN}{code}{C.RESET}"
    if code in (401, 403):
        return f"{C.YELLOW}{code}{C.RESET}"
    if 400 <= code < 500:
        return f"{C.GRAY}{code}{C.RESET}"
    if code >= 500:
        return f"{C.MAGENTA}{code}{C.RESET}"
    return str(code)


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH")
DEFAULT_FILTER = {204, 301, 302, 401, 403, 404}


def build_session(retries: int, timeout: float, verify_ssl: bool, user_agent: str):
    """Build a requests Session with connection pooling and retry."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=0.3,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=frozenset(HTTP_METHODS),
    )
    adapter = HTTPAdapter(
        pool_connections=64,
        pool_maxsize=64,
        max_retries=retry,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": user_agent})
    session.verify = verify_ssl
    session._timeout = timeout  # stash for callers
    return session


def load_lines(path: str):
    """Load a file, stripping blanks and comments."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [
                line.strip()
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except FileNotFoundError:
        err(f"File not found: {path}")
        sys.exit(1)
    except PermissionError:
        err(f"Permission denied: {path}")
        sys.exit(1)


def probe(session, url, methods, timeout):
    """Probe a single URL across the requested HTTP methods."""
    results = {}
    for method in methods:
        try:
            resp = session.request(
                method, url, timeout=timeout, allow_redirects=False
            )
            results[method] = resp.status_code
        except requests.exceptions.Timeout:
            results[method] = "TIMEOUT"
        except requests.exceptions.ConnectionError:
            results[method] = "CONNERR"
        except requests.exceptions.RequestException:
            results[method] = "ERROR"
    return url, results


def is_interesting(results, filter_codes):
    """Any status outside the filter set counts as interesting."""
    for code in results.values():
        if isinstance(code, int) and code not in filter_codes:
            return True
        if isinstance(code, str):  # network errors aren't "interesting" hits
            continue
    return False


def format_result_line(path, results, methods):
    """Format an interesting result for stdout."""
    parts = [f"{C.BOLD}{path:<40}{C.RESET}"]
    for m in methods:
        code = results.get(m, "-")
        if isinstance(code, int):
            parts.append(f"{m}:{status_color(code)}")
        else:
            parts.append(f"{m}:{C.RED}{code}{C.RESET}")
    return "  ".join(parts)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
class Runner:
    def __init__(self, args):
        self.args = args
        self.session = build_session(
            retries=args.retries,
            timeout=args.timeout,
            verify_ssl=not args.insecure,
            user_agent=args.user_agent,
        )
        self.methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]
        self.filter_codes = set()
        for token in args.filter.split(","):
            token = token.strip()
            if token.isdigit():
                self.filter_codes.add(int(token))
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.completed = 0
        self.total = 0
        self.hits = 0
        self.output_fh = None
        if args.output:
            try:
                self.output_fh = open(args.output, "w", encoding="utf-8")
                self.output_fh.write("path,method,status\n")
            except OSError as e:
                err(f"Cannot open output file: {e}")
                sys.exit(1)

    def build_targets(self, words, actions):
        """Generate (display_path, full_url) pairs."""
        target = self.args.target.rstrip("/")
        for word in words:
            word = word.strip("/")
            if actions:
                for action in actions:
                    action = action.strip("/")
                    path = f"/{word}/{action}" if action else f"/{word}"
                    yield path, f"{target}{path}"
            else:
                path = f"/{word}"
                yield path, f"{target}{path}"

    def progress(self, path):
        if self.args.quiet:
            return
        with self.lock:
            self.completed += 1
            pct = (self.completed / self.total * 100) if self.total else 0
            bar = f"[{self.completed}/{self.total} {pct:5.1f}%]"
            display = path[:60].ljust(60)
            sys.stdout.write(
                f"\r{C.DIM}{bar} probing {display}{C.RESET}"
            )
            sys.stdout.flush()

    def handle_result(self, path, url, results):
        if self.stop_event.is_set():
            return
        if is_interesting(results, self.filter_codes):
            with self.lock:
                self.hits += 1
                # Clear progress line, then print result
                sys.stdout.write("\r" + " " * 100 + "\r")
                print(format_result_line(path, results, self.methods))
                if self.output_fh:
                    for method, code in results.items():
                        self.output_fh.write(f"{path},{method},{code}\n")
                    self.output_fh.flush()

    def run(self, words, actions):
        target_pairs = list(self.build_targets(words, actions))
        self.total = len(target_pairs)

        info(f"Target:    {C.BOLD}{self.args.target}{C.RESET}")
        info(f"Methods:   {', '.join(self.methods)}")
        info(f"Threads:   {self.args.threads}")
        info(f"Requests:  {self.total * len(self.methods)} "
             f"({self.total} paths × {len(self.methods)} methods)")
        info(f"Filtering: {sorted(self.filter_codes)}")
        print()

        # Print column header
        header = f"{'PATH':<40}  " + "  ".join(f"{m:<8}" for m in self.methods)
        print(f"{C.BOLD}{header}{C.RESET}")
        print(C.GRAY + "-" * len(header) + C.RESET)

        timeout = self.args.timeout

        try:
            with ThreadPoolExecutor(max_workers=self.args.threads) as pool:
                futures = {
                    pool.submit(probe, self.session, url, self.methods, timeout): path
                    for path, url in target_pairs
                }
                for future in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    path = futures[future]
                    try:
                        url, results = future.result()
                        self.progress(path)
                        self.handle_result(path, url, results)
                    except Exception as e:
                        err(f"Worker failed on {path}: {e}")
        except KeyboardInterrupt:
            self.stop_event.set()
            warn("Interrupted by user, shutting down...")

        # Final newline to clear progress
        sys.stdout.write("\r" + " " * 100 + "\r")
        sys.stdout.flush()

        print()
        good(f"Done. {self.hits} interesting result(s) out of {self.completed} paths probed.")
        if self.output_fh:
            self.output_fh.close()
            info(f"Results written to {self.args.output}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        prog="pathhunter",
        description="HTTP path and method enumeration tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  pathhunter -t https://example.com -w words.txt
  pathhunter -t https://example.com -w words.txt -a actions.txt -T 50
  pathhunter -t https://example.com -w words.txt -m GET,POST -o results.csv
        """,
    )
    parser.add_argument("-t", "--target", required=True,
                        help="target host/URL (e.g. https://example.com)")
    parser.add_argument("-w", "--wordlist", required=True,
                        help="path wordlist file")
    parser.add_argument("-a", "--actionlist",
                        help="optional action wordlist appended to each path")
    parser.add_argument("-m", "--methods", default=",".join(HTTP_METHODS),
                        help=f"comma-separated HTTP methods (default: {','.join(HTTP_METHODS)})")
    parser.add_argument("-T", "--threads", type=int, default=20,
                        help="number of worker threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="per-request timeout in seconds (default: 10)")
    parser.add_argument("--retries", type=int, default=1,
                        help="retries on 5xx responses (default: 1)")
    parser.add_argument("-f", "--filter",
                        default=",".join(str(c) for c in sorted(DEFAULT_FILTER)),
                        help=f"comma-separated status codes to hide "
                             f"(default: {','.join(str(c) for c in sorted(DEFAULT_FILTER))})")
    parser.add_argument("-u", "--user-agent",
                        default="PathHunter/1.0",
                        help="User-Agent header (default: PathHunter/1.0)")
    parser.add_argument("-o", "--output",
                        help="write CSV results to file")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="skip SSL certificate verification")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress progress output")
    parser.add_argument("--no-banner", action="store_true",
                        help="skip the banner")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.no_banner:
        print(BANNER)

    # Validate target scheme
    if not args.target.startswith(("http://", "https://")):
        warn(f"No scheme on target, defaulting to http:// — use https:// if needed")
        args.target = "http://" + args.target

    info(f"Loading wordlist: {args.wordlist}")
    words = load_lines(args.wordlist)
    info(f"  {len(words)} words loaded")

    actions = []
    if args.actionlist:
        info(f"Loading actions:  {args.actionlist}")
        actions = load_lines(args.actionlist)
        info(f"  {len(actions)} actions loaded")
    print()

    runner = Runner(args)

    # Graceful Ctrl+C
    def _sigint(_sig, _frame):
        runner.stop_event.set()
        warn("Caught SIGINT, finishing in-flight requests...")
    signal.signal(signal.SIGINT, _sigint)

    runner.run(words, actions)


if __name__ == "__main__":
    main()

