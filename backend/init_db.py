"""
Database initialization and migration script for NIDS.
Connects to PostgreSQL, creates 'nids_db' if it does not exist,
and executes Alembic migrations to apply initial tables and constraints.
"""
import subprocess
import sys
import psycopg
from psycopg import sql

# Ensure backend directory is in sys.path
sys.path.insert(0, ".")

from app.core.config import settings
from app.core.logging import logger


def init_database() -> bool:
    print("[*] Checking PostgreSQL connectivity...")

    # Connect to the default 'postgres' database to check/create 'nids_db'
    conn_params = {
        "host": settings.POSTGRES_HOST,
        "port": settings.POSTGRES_PORT,
        "user": settings.POSTGRES_USER,
        "password": settings.POSTGRES_PASSWORD,
        "dbname": "postgres",
    }

    try:
        with psycopg.connect(**conn_params, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM pg_database WHERE datname = %s",
                    (settings.POSTGRES_DB,),
                )
                exists = cur.fetchone()
                if not exists:
                    print(f"[*] Database '{settings.POSTGRES_DB}' does not exist. Creating...")
                    cur.execute(
                        sql.SQL("CREATE DATABASE {}").format(
                            sql.Identifier(settings.POSTGRES_DB)
                        )
                    )
                    print(f"[+] Database '{settings.POSTGRES_DB}' created successfully.")
                else:
                    print(f"[*] Database '{settings.POSTGRES_DB}' already exists.")

    except psycopg.OperationalError as op_err:
        print(f"[!] Unable to connect to PostgreSQL server: {op_err}")
        print("    Please verify POSTGRES_PASSWORD in your .env file or local server status.")
        return False
    except Exception as exc:
        print(f"[!] Error during database check/creation: {exc}")
        return False

    # Apply Alembic migrations
    print("[*] Running Alembic migrations (upgrade head)...")
    res = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "head"],
        capture_output=True,
        text=True,
    )
    if res.returncode == 0:
        print("[+] Migrations applied successfully!")
        if res.stdout:
            print(res.stdout.strip())
        return True
    else:
        print(f"[!] Migration failed with return code {res.returncode}:")
        if res.stderr:
            print(res.stderr.strip())
        return False


if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)
