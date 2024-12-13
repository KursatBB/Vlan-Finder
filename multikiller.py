import os
import subprocess

# Grep ile Python processlerini bul
process = subprocess.Popen(["ps", "aux"], stdout=subprocess.PIPE)
output, error = process.communicate()

# Çıktıyı satır satır işle
lines = output.decode().splitlines()

# PID'leri saklamak için bir liste
pids = []

for line in lines:
    if "python" in line and "grep" not in line:  # "python" ve "grep" dışında olan satırları al
        columns = line.split()  # Satırı sütunlara ayır
        pids.append(columns[1])  # 2. sütunu (PID) al

# PID'leri öldür
for pid in pids:
    try:
        os.kill(int(pid), 9)  # PID'yi int'e çevirip processi öldür
        print(f"Process {pid} killed.")
    except Exception as e:
        print(f"Failed to kill process {pid}: {e}")
