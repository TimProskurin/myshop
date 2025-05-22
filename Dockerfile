FROM python:3.13-slim

WORKDIR /app


RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg2 && \
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor > /usr/share/keyrings/postgresql.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] http://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    netcat-traditional \
    postgresql-client-16 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt --root-user-action=ignore
COPY alembic.ini /app/alembic.ini
COPY alembic /app/alembic


COPY ./app /app/app
COPY wait-for.sh /app/wait-for.sh

RUN chmod +x /app/wait-for.sh

CMD ["uvicorn", "app.main:application", "--host", "0.0.0.0", "--port", "8000"]
