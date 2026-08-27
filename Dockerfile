FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia todos los módulos del relay (main, store, auth, …). Usar el glob evita
# que un módulo nuevo se quede fuera del contenedor (pasó con auth.py).
COPY *.py ./

# Panel WEB (build de Flutter Web servido en /panel, mismo origen que la API).
COPY panel_web ./panel_web

# Consola WEB dedicada (dashboard de escritorio servido en /console).
COPY console ./console

# Fly.io / hosts inyectan PORT; por defecto 8080.
ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
