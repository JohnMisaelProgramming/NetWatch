"""
NetWatch Attack Simulation Test Script
=======================================
Sends a flood of HTTP requests to test NetWatch's detection capabilities.

Usage:
    python attack_test.py                      # Default: attack ShopSafe (port 8001)
    python attack_test.py --target netwatch    # Attack NetWatch directly (port 8000)
    python attack_test.py --target shopsafe    # Attack ShopSafe (port 8001)
    python attack_test.py --requests 500       # Send 500 requests
    python attack_test.py --threads 50         # Use 50 concurrent threads

What this tests:
    - NetWatch's traffic logging (both direct and via ShopSafe forwarding)
    - DDoS spike detection by the run_detector daemon
    - Rate-limit violation detection
    - Auto-blocking (if enabled in System Settings)
    - Device blocking (this script uses a distinctive User-Agent: "AttackBot/1.0")
"""

import argparse
import requests
from concurrent.futures import ThreadPoolExecutor
import threading

# Reuse connections for better performance
session = requests.Session()
lock = threading.Lock()

success = 0
failed = 0
is_blocked = False


def send_request(i, url, user_agent):
    global success, failed, is_blocked

    # If the target has blocked us, exit early and stop making requests
    if is_blocked:
        return

    try:
        response = session.get(
            url,
            timeout=5,
            headers={'User-Agent': user_agent},
        )

        if response.status_code == 403:
            with lock:
                if not is_blocked:
                    is_blocked = True
                    print(f"\n[!] Mitigated: Request {i} returned 403 Forbidden.")
                    print("[!] NetWatch has successfully blocked this attack! Terminating simulation...")
            return

        with lock:
            success += 1
            if i % 50 == 0 or i < 10:
                print(f"[{i}] Status: {response.status_code}")

    except Exception as e:
        with lock:
            failed += 1
            if failed <= 5:
                print(f"[{i}] Error: {e}")


def main():
    parser = argparse.ArgumentParser(description='NetWatch Attack Simulation Test')
    parser.add_argument(
        '--target', choices=['netwatch', 'shopsafe'], default='shopsafe',
        help='Which application to attack (default: shopsafe on port 8001)'
    )
    parser.add_argument(
        '--requests', type=int, default=200,
        help='Total number of requests to send (default: 200)'
    )
    parser.add_argument(
        '--threads', type=int, default=20,
        help='Number of concurrent threads (default: 20)'
    )
    parser.add_argument(
        '--user-agent', type=str, default='AttackBot/1.0',
        help='User-Agent string to use (default: AttackBot/1.0)'
    )
    parser.add_argument(
        '--path', type=str, default='/',
        help='URL path to attack (default: /)'
    )
    args = parser.parse_args()

    if args.target == 'netwatch':
        base_url = f'http://127.0.0.1:8000{args.path}'
    else:
        base_url = f'http://127.0.0.1:8001{args.path}'

    print("=" * 50)
    print("  NetWatch Attack Simulation Test")
    print("=" * 50)
    print(f"  Target:      {args.target.upper()} → {base_url}")
    print(f"  Requests:    {args.requests}")
    print(f"  Threads:     {args.threads}")
    print(f"  User-Agent:  {args.user_agent}")
    print("=" * 50)
    print()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(send_request, i, base_url, args.user_agent)
            for i in range(args.requests)
        ]
        # Wait for all futures to complete
        for f in futures:
            f.result()

    print()
    print("=" * 50)
    print("  ATTACK SUMMARY")
    print("=" * 50)
    print(f"  Total Requests : {args.requests}")
    print(f"  Successful     : {success}")
    print(f"  Failed/Blocked : {failed}")
    print(f"  Auto-Mitigated : {'YES — 403 received' if is_blocked else 'No'}")
    print("=" * 50)


if __name__ == "__main__":
    main()