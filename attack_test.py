# import requests

# URL = "http://127.0.0.1:8000/"

# for i in range(100000000):
#     try:
#         response = requests.get(URL)
#         print(f"Request {i+1}: {response.status_code}")
#     except Exception as e:
#         print(f"Error: {e}")


import requests
from concurrent.futures import ThreadPoolExecutor
import threading

URL = "http://127.0.0.1:8000/"
TOTAL_REQUESTS = 1000000
THREADS = 100

# Reuse connections for better performance
session = requests.Session()
lock = threading.Lock()

success = 0
failed = 0
is_blocked = False

def send_request(i):
    global success, failed, is_blocked

    # If the target has blocked us, exit early and stop making requests
    if is_blocked:
        return

    try:
        response = session.get(URL, timeout=5)

        if response.status_code == 403:
            with lock:
                if not is_blocked:
                    is_blocked = True
                    print(f"\n[!] Mitigated: Request {i} returned 403 Forbidden.")
                    print("[!] NetWatch has successfully blocked this IP address! Terminating simulation...")
            return

        with lock:
            success += 1
            print(f"[{i}] Status: {response.status_code}")

    except Exception as e:
        with lock:
            failed += 1
            print(f"[{i}] Error: {e}")

def main():
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(send_request, range(TOTAL_REQUESTS))

    print("\n========== SUMMARY ==========")
    print(f"Total Requests : {TOTAL_REQUESTS}")
    print(f"Successful     : {success}")
    print(f"Failed         : {failed}")

if __name__ == "__main__":
    main()