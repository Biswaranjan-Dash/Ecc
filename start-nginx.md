# Nginx Setup for ECC Project

## Configuration Overview

This Nginx configuration combines:
- **Backend API** (FastAPI on port 8000) → `http://localhost:9000/`
- **Frontend Dashboard** (on port 5500) → `http://localhost:9000/dashboard`

## Installation

### Windows

1. **Download Nginx:**
   - Go to http://nginx.org/en/download.html
   - Download the stable Windows version
   - Extract to `C:\nginx` (or your preferred location)

2. **Copy Configuration:**
   ```powershell
   # Copy nginx.conf to Nginx directory
   Copy-Item .\nginx.conf C:\nginx\conf\nginx.conf
   ```

3. **Start Nginx:**
   ```powershell
   cd C:\nginx
   .\nginx.exe
   ```

4. **Test Configuration:**
   ```powershell
   .\nginx.exe -t
   ```

5. **Reload Configuration (after changes):**
   ```powershell
   .\nginx.exe -s reload
   ```

6. **Stop Nginx:**
   ```powershell
   .\nginx.exe -s stop
   ```

### Alternative: Using Docker

Create `docker-compose.yml`:

```yaml
version: '3.8'
services:
  nginx:
    image: nginx:latest
    ports:
      - "9000:9000"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - backend
      - frontend
    network_mode: host
```

Then run:
```powershell
docker-compose up -d
```

## Usage

Once Nginx is running:

- **Backend API:** http://localhost:9000/
  - API endpoints: http://localhost:9000/public-key
  - WebSocket: ws://localhost:9000/ws
  - Health check: http://localhost:9000/ping

- **Frontend Dashboard:** http://localhost:9000/dashboard
  - Access the WebSocket test page
  - View real-time health data

## Testing

1. **Start Backend:**
   ```powershell
   cd backend
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Start Frontend:**
   ```powershell
   cd frontend
   # Start your frontend dev server on port 5500
   # (or open websocket-test.html with a local server)
   ```

3. **Start Nginx:**
   ```powershell
   cd C:\nginx
   .\nginx.exe
   ```

4. **Test:**
   - Backend: http://localhost:9000/ping
   - Frontend: http://localhost:9000/dashboard

## Troubleshooting

- **Port already in use:** Check if port 9000 is available
- **502 Bad Gateway:** Make sure both backend (8000) and frontend (5500) are running
- **Configuration errors:** Run `nginx -t` to test configuration
- **View logs:** Check `C:\nginx\logs\error.log`

## Notes

- WebSocket connections are supported on both routes
- CORS is handled by the FastAPI backend
- Static assets are properly proxied to the frontend
