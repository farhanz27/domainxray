# Stage 1: Build Vue frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Python runtime
FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY server.py ./
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

EXPOSE 8001
CMD ["uvicorn", "server:api", "--host", "0.0.0.0", "--port", "8001"]
