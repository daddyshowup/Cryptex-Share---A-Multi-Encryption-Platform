#!/usr/bin/env bash

export DISPLAY=:99

# Start virtual display
WIDTH="${DISPLAY_WIDTH:-1920}"
HEIGHT="${DISPLAY_HEIGHT:-1080}"
DEPTH="${DISPLAY_DEPTH:-24}"

Xvfb :99 -screen 0 "${WIDTH}x${HEIGHT}x${DEPTH}" -ac +extension GLX +render -noreset &
XVFB_PID=$!

# Wait until X is ready (important)
for i in {1..30}; do
  if command -v xdpyinfo >/dev/null 2>&1 && xdpyinfo -display :99 >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

# Window manager
fluxbox &
FLUX_PID=$!

# Start VNC (disable features that sometimes crash inside containers)
x11vnc -display :99 -nopw -forever -shared -rfbport 5900 -noxdamage -xkb &
VNC_PID=$!

# Start noVNC (browser)
websockify --web=/usr/share/novnc/ 6080 localhost:5900 &
NOVNC_PID=$!

# Run the Tkinter app
python Cryptex_Share.py &

# Keep container alive as long as VNC/noVNC are running
wait $VNC_PID
