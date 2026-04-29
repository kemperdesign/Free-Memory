import psutil
import requests
import time

API_URL = "http://localhost:3013/api/report"

def gather_data():
    memory = psutil.virtual_memory()
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            info = proc.info
            processes.append({
                "pid": info['pid'],
                "name": info['name'],
                "cpu": info['cpu_percent'],
                "memory": info['memory_info'].rss / (1024 * 1024)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return {
        "os": "Windows/Machine",
        "cpuUsage": psutil.cpu_percent(interval=1),
        "memory": {
            "total": memory.total / (1024 * 1024),
            "used": memory.used / (1024 * 1024),
            "percent": memory.percent
        },
        "processes": sorted(processes, key=lambda x: x['memory'], reverse=True)[:50]
    }

print(f"Connecting to PC Pulse at {API_URL}...")
while True:
    try:
        data = gather_data()
        requests.post(API_URL, json=data)
        time.sleep(2)
    except Exception as e:
        print(f"Sync error: {e}")
        time.sleep(5)
