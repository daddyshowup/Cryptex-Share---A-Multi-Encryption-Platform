FROM python:3.11-slim

WORKDIR /app

# Tkinter + GUI-in-browser stack (Xvfb + VNC + noVNC)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-tk tk \
    xvfb x11vnc novnc websockify fluxbox \
    x11-utils \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 6080

CMD ["bash", "run_gui_novnc.sh"]
