# Docker Setup for ECC Project

This setup runs the entire stack (Nginx, Backend, Frontend) in Docker containers.

## Prerequisites

- Docker Desktop for Windows installed
- Docker Compose installed (included with Docker Desktop)

## Quick Start

1. **Build and Start All Services:**
   ```powershell
   docker-compose up -d --build
   ```

2. **View Logs:**
   ```powershell
   # All services
   docker-compose logs -f

   # Specific service
   docker-compose logs -f nginx
   docker-compose logs -f backend
   docker-compose logs -f frontend
   ```

3. **Check Status:**
   ```powershell
   docker-compose ps
   ```

4. **Stop All Services:**
   ```powershell
   docker-compose down
   ```

5. **Restart Services:**
   ```powershell
   docker-compose restart
   ```

## Access Points

Once running, access via:

- **Backend API:** http://localhost:9000/
  - Endpoints: http://localhost:9000/public-key
  - WebSocket: ws://localhost:9000/ws
  - Health: http://localhost:9000/ping

- **Frontend Dashboard:** http://localhost:9000/dashboard

## Individual Service Commands

### Backend Only
```powershell
docker-compose up -d backend
docker-compose logs -f backend
docker-compose restart backend
```

### Frontend Only
```powershell
docker-compose up -d frontend
docker-compose logs -f frontend
docker-compose restart frontend
```

### Nginx Only
```powershell
docker-compose up -d nginx
docker-compose logs -f nginx
docker-compose restart nginx
```

## Troubleshooting

### Port Conflicts
If ports 8000, 5500, or 9000 are already in use:
```powershell
# Check what's using the ports
netstat -ano | findstr :9000
netstat -ano | findstr :8000
netstat -ano | findstr :5500

# Kill the process (replace PID)
taskkill /PID <PID> /F
```

### Rebuild After Code Changes
```powershell
docker-compose down
docker-compose up -d --build
```

### View Container Details
```powershell
# List containers
docker ps

# Inspect container
docker inspect ecc-nginx
docker inspect ecc-backend
docker inspect ecc-frontend

# Enter container shell
docker exec -it ecc-backend /bin/sh
docker exec -it ecc-frontend /bin/sh
docker exec -it ecc-nginx /bin/sh
```

### Clean Up Everything
```powershell
# Stop and remove containers
docker-compose down

# Remove volumes
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

## Development Workflow

### Hot Reload
The containers support hot reload:
- **Backend:** Changes to Python files auto-reload uvicorn
- **Frontend:** Changes auto-rebuild (if using Vite/React dev server)

### Update Dependencies

**Backend:**
```powershell
# Update requirements.txt, then rebuild
docker-compose up -d --build backend
```

**Frontend:**
```powershell
# Update package.json, then rebuild
docker-compose up -d --build frontend
```

## Testing the Setup

1. **Start everything:**
   ```powershell
   docker-compose up -d --build
   ```

2. **Test backend:**
   ```powershell
   curl http://localhost:9000/ping
   ```

3. **Test frontend:**
   Open browser: http://localhost:9000/dashboard

4. **Test WebSocket:**
   Open: http://localhost:9000/dashboard
   Should connect via WebSocket

5. **Run client simulator:**
   ```powershell
   cd backend
   python client_esp.py
   ```

## Production Deployment

For production, modify `docker-compose.yml`:

1. Remove `network_mode: "host"` 
2. Use proper networking
3. Add environment variables
4. Use production frontend build
5. Add SSL/TLS certificates
6. Configure proper logging

## Notes

- Using `network_mode: "host"` for simplicity (localhost communication)
- Nginx logs are stored in `./logs` directory
- Services restart automatically on failure
- All services run in detached mode with `-d` flag
