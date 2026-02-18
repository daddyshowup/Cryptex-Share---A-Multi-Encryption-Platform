#  Install + verify prerequisites (Windows)

 - Install Docker Desktop for Windows

 - In Docker Desktop settings, ensure:

 - Use WSL 2 based engine = ON

 - WSL integration enabled for your distro (Ubuntu etc.)

 - Reboot if asked.

 - Open Docker Desktop and wait until it says Running.

#  Verify from PowerShell (this is important)

 - Open PowerShell and run:

 - docker --version
 - docker compose version


 - Expected: both print a version.
 - If docker compose version fails, try:

 - docker-compose --version


 - If none work, Docker is not installed correctly (that’s exactly when Windows starts asking to open “docker-compose” in a browser).

#  Clone and run Cryptex Share

 - From PowerShell:

 - git clone <your-repo-url>
 - cd <repo-folder-name>
 - docker compose up --build -d

 - Then open in browser:

 - http://localhost:6080/vnc.html

 - (If that page shows directory listing, open vnc.html not just localhost:6080/)

 - To stop:

 - docker compose down

# #################################################################################################################################

# Docker Setup For (Kali Linux)
# Requirements

 - Install Docker + Docker Compose plugin:

 - sudo apt update
 - sudo apt install -y docker.io docker-compose-plugin
 - sudo systemctl enable --now docker
 - sudo usermod -aG docker $USER
 - newgrp docker


 - Check versions:

 - docker --version
 - docker compose version

# Clone the repository
 - git clone <YOUR_GITHUB_REPO_URL>
 - cd Cryptex-Share---A-Multi-Encryption-Platform

# Build and run (background)
 - docker compose up --build -d

# Open the GUI in browser

 - Open:

 - http://localhost:6080/vnc.html

 - (If it shows a directory listing, open vnc.html manually.)

# Check status / logs

Check if it’s running:

 - docker compose ps

View logs:

 - docker compose logs -f

Stop everything:

 - docker compose down

Restart:

 - docker compose up -d