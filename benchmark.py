import subprocess
import time
import psutil
import sqlite3


def run_attack(command):
    print(f"Running: {command}")
    start = time.time()
    proc = subprocess.Popen(command, shell=True)
    time.sleep(5)
    proc.terminate()
    return time.time() - start


def log_metrics(db_path="benchmark.db"):
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent
    db_path = "packet_log.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS metrics (cpu REAL, mem REAL, ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("INSERT INTO metrics (cpu, mem) VALUES (?, ?)", (cpu, mem))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    # Example: benchmark port scan
    duration = run_attack("nmap -sS localhost")
    log_metrics()
    print(f"Scan test completed in {duration:.2f} sec")
