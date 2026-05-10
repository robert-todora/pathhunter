# PathHunter

HTTP path and method enumeration tool. Combines a path wordlist with an optional action list and probes each combination across multiple HTTP methods, surfacing only the responses that don't match a noise filter.

```
   ___      _   _      _  _              _
  / _ \__ _| |_| |_   | || |_  _ _ _  __| |_ ___ _ _
 |  _/ _` |  _| ' \  | __ | || | ' \/ _|  _/ -_) '_|
 |_| \__,_|\__|_||_| |_||_|\_,_|_||_\__|\__\___|_|
        HTTP path & method enumeration tool
```

## Features

- Threaded request engine using `ThreadPoolExecutor` and a pooled `requests.Session`
- Per-method probing: `GET`, `POST`, `PUT`, `PATCH` by default, configurable with `-m`
- Color-coded status codes and live progress bar
- Configurable status-code filter to hide noise (`204/301/302/401/403/404` by default)
- CSV output with `-o`
- Configurable timeout, retries, User-Agent, and TLS verification
- Graceful Ctrl+C handling

## Install

```bash
git clone https://github.com/robert-todora/pathhunter.git
cd pathhunter
pip install -r requirements.txt
```

`requirements.txt`:
```
requests>=2.31.0
```

## Usage

```bash
# basic
./pathhunter.py -t https://example.com -w wordlist.txt

# with action list and 50 threads
./pathhunter.py -t https://example.com -w words.txt -a actions.txt -T 50

# limit to GET and POST, save CSV
./pathhunter.py -t https://example.com -w words.txt -m GET,POST -o results.csv

# self-signed cert, custom UA, hide more codes
./pathhunter.py -t https://internal.lab -w words.txt -k \
                -u "Mozilla/5.0" -f 204,301,302,401,403,404,405
```

### Options

| Flag | Description |
|---|---|
| `-t, --target` | Target host or URL (required) |
| `-w, --wordlist` | Path wordlist (required) |
| `-a, --actionlist` | Optional action list appended to each path |
| `-m, --methods` | Comma-separated HTTP methods (default: `GET,POST,PUT,PATCH`) |
| `-T, --threads` | Worker threads (default: 20) |
| `--timeout` | Per-request timeout in seconds (default: 10) |
| `--retries` | Retries on 5xx (default: 1) |
| `-f, --filter` | Status codes to hide (default: `204,301,302,401,403,404`) |
| `-u, --user-agent` | User-Agent header |
| `-o, --output` | Write CSV results to file |
| `-k, --insecure` | Skip TLS verification |
| `-q, --quiet` | Suppress progress output |
| `--no-banner` | Skip the banner |

## Responsible use

Only run this against systems you own or have explicit written permission to test.

## License

MIT

