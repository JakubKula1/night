"""
Environment Manager — Deploys and manages the DVWA Docker test environment.
"""

import subprocess
import sys
import time


DVWA_CONTAINER = "dvwa-test"
DVWA_IMAGE = "vulnerables/web-dvwa"
DVWA_PORT = 8080
DVWA_URL = f"http://127.0.0.1:{DVWA_PORT}"


def _run(cmd, capture=True, check=False):
    result = subprocess.run(
        cmd, shell=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True
    )
    return result


def is_docker_running():
    r = _run("docker info")
    return r.returncode == 0


def container_exists():
    r = _run(f"docker inspect {DVWA_CONTAINER}")
    return r.returncode == 0


def container_running():
    r = _run(f"docker inspect -f '{{{{.State.Running}}}}' {DVWA_CONTAINER}")
    return r.returncode == 0 and r.stdout.strip() == 'true'


def start_container():
    if container_running():
        print(f"[+] DVWA container '{DVWA_CONTAINER}' is already running at {DVWA_URL}")
        return True

    if container_exists():
        print(f"[*] Starting existing container '{DVWA_CONTAINER}'...")
        r = _run(f"docker start {DVWA_CONTAINER}")
        if r.returncode != 0:
            print(f"[-] Failed to start container: {r.stderr.strip()}")
            return False
    else:
        print(f"[*] Pulling and running DVWA container...")
        r = _run(
            f"docker run --name {DVWA_CONTAINER} -d -p {DVWA_PORT}:80 {DVWA_IMAGE}",
            capture=False
        )
        if r.returncode != 0:
            print(f"[-] Failed to start DVWA container.")
            return False

    print(f"[*] Waiting for DVWA to become ready...")
    for i in range(30):
        time.sleep(2)
        r = _run(f"curl -s -o /dev/null -w '%{{http_code}}' {DVWA_URL}")
        if r.stdout.strip() in ('200', '302'):
            print(f"[+] DVWA is ready at {DVWA_URL}")
            return True
        sys.stdout.write(f"\r    Waiting... ({i*2}s)")
        sys.stdout.flush()
    print("\n[-] DVWA did not become ready in time.")
    return False


def stop_container():
    if not container_running():
        print(f"[*] Container '{DVWA_CONTAINER}' is not running.")
        return
    print(f"[*] Stopping DVWA container...")
    _run(f"docker stop {DVWA_CONTAINER}")
    print(f"[+] Stopped.")


def remove_container():
    stop_container()
    if container_exists():
        print(f"[*] Removing DVWA container...")
        _run(f"docker rm {DVWA_CONTAINER}")
        print(f"[+] Removed.")


def ensure_environment():
    """Ensure Docker and DVWA are running. Returns DVWA target URL or None."""
    if not is_docker_running():
        print("[-] Docker is not running. Please start Docker first.")
        return None
    if not start_container():
        return None
    return DVWA_URL


def print_status():
    if not is_docker_running():
        print("  Docker: NOT running")
        return
    print("  Docker: running")
    if container_running():
        print(f"  DVWA:   running at {DVWA_URL}")
    elif container_exists():
        print(f"  DVWA:   stopped (run 'night test env start' to start)")
    else:
        print(f"  DVWA:   not deployed (run 'night test env setup' to deploy)")