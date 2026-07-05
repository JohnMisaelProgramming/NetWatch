import time
import random
import threading
import requests
from django.utils import timezone
from .models import SimulationRun

# In-memory registry of active threads and stop flags
# Format: { simulation_id: stop_event }
_active_simulations = {}
_registry_lock = threading.Lock()

def start_simulation_thread(simulation_id, base_url):
    """
    Spawns a background thread to run the HTTP request generator.
    """
    stop_event = threading.Event()
    with _registry_lock:
        _active_simulations[simulation_id] = stop_event

    thread = threading.Thread(
        target=run_traffic_simulation,
        args=(simulation_id, base_url, stop_event),
        daemon=True
    )
    thread.start()
    return thread

def stop_simulation_thread(simulation_id):
    """
    Signals a running simulation thread to stop.
    """
    with _registry_lock:
        stop_event = _active_simulations.get(simulation_id)
        if stop_event:
            stop_event.set()
            return True
    return False

def run_traffic_simulation(simulation_id, base_url, stop_event):
    """
    Generates local HTTP traffic in a loop, simulating client IP addresses
    and updating metrics in the database.
    """
    try:
        # Fetch simulation parameters from DB
        sim = SimulationRun.objects.get(pk=simulation_id)
        sim.status = 'running'
        sim.started_at = timezone.now()
        sim.save()

        # Generate a pool of distinct simulated IPs
        ip_pool = []
        for _ in range(max(1, sim.simulated_ips_count)):
            ip_pool.append(
                f"{random.randint(1, 223)}.{random.randint(1, 254)}."
                f"{random.randint(1, 254)}.{random.randint(1, 254)}"
            )

        target_url = f"{base_url.rstrip('/')}{sim.target_endpoint}"
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'NetWatch-Simulation-Agent/1.0',
            'Connection': 'keep-alive',
        })

        requests_sent = 0
        requests_blocked = 0
        last_db_update = time.time()

        for i in range(sim.num_requests):
            # Check if simulation was stopped via the UI
            if stop_event.is_set():
                break

            # Choose a random IP from our simulated pool
            simulated_ip = random.choice(ip_pool)
            headers = {
                'HTTP_X_NETWATCH_SIMULATED_IP': simulated_ip,
                'X-NetWatch-Simulated-IP': simulated_ip,
            }

            try:
                # Perform the HTTP request
                # We use a short timeout to prevent the thread hanging if the server is slow
                response = session.get(target_url, headers=headers, timeout=3)
                
                if response.status_code == 403:
                    requests_blocked += 1
                else:
                    requests_sent += 1
            except requests.RequestException:
                # If the server is down or times out, count it as failed/blocked
                requests_blocked += 1

            # Throttle DB writes: update database every 1 second
            if time.time() - last_db_update > 1.0:
                SimulationRun.objects.filter(pk=simulation_id).update(
                    requests_sent=requests_sent,
                    requests_blocked=requests_blocked
                )
                last_db_update = time.time()

            # Apply delay between requests
            if sim.delay_ms > 0:
                time.sleep(sim.delay_ms / 1000.0)

        # Final Database Sync
        sim.refresh_from_db()
        sim.requests_sent = requests_sent
        sim.requests_blocked = requests_blocked
        sim.status = 'stopped' if stop_event.is_set() else 'completed'
        sim.ended_at = timezone.now()
        sim.save()

    except Exception as e:
        # Handle failures gracefully so the thread does not silent-crash
        try:
            SimulationRun.objects.filter(pk=simulation_id).update(
                status='failed',
                error_message=str(e),
                ended_at=timezone.now()
            )
        except Exception:
            pass
    finally:
        # Cleanup thread registry
        with _registry_lock:
            _active_simulations.pop(simulation_id, None)
