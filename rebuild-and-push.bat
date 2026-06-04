@echo off
echo Construyendo imagen con SSE...
docker build -t ghcr.io/m-risk/redmine-mcp:7.0.10 .

echo Subiendo a GitHub Container Registry...
docker push ghcr.io/m-risk/redmine-mcp:7.0.10

echo Listo! El servicio estara disponible en el puerto 8000
