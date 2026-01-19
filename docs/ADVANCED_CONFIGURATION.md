# Advanced Configuration & Scaling

This guide covers advanced deployment scenarios, specifically setting up PostgreSQL for high-volume logging and migrating data from SQLite.

## 1. When to use PostgreSQL?
By default, FauxSSH uses **SQLite** (`data/honeypot.sqlite`). This is perfect for standalone deployments and testing.

**Switch to PostgreSQL if:**
- You expect high traffic (>10,000 sessions/day).
- You are running a cluster of honeypots and want centralized logging.
- You need concurrent write performance (SQLite locks the DB on write).
- You want to connect external BI tools (Grafana, Tableau) to the data.

## 2. PostgreSQL Setup (Ubuntu/Debian)

### 2.1 Install PostgreSQL
```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib libpq-dev
```

### 2.2 Create User and Database
Switch to the postgres user and create the secure credentials:

```bash
sudo -u postgres psql
```

Inside the SQL prompt:
```sql
-- Create a dedicated user
CREATE USER honeypot_user WITH PASSWORD 'SecurePassword123!';

-- Create the database
CREATE DATABASE honeypot_logs OWNER honeypot_user;

-- Grant privileges (if needed, owner usually has full rights)
GRANT ALL PRIVILEGES ON DATABASE honeypot_logs TO honeypot_user;

\q
```

### 2.3 Allow Remote Connections (Optional)
If your database is on a different server than the honeypot:

1.  Edit `/etc/postgresql/14/main/postgresql.conf`:
    ```ini
    listen_addresses = '*'
    ```
2.  Edit `/etc/postgresql/14/main/pg_hba.conf` to whitelist the honeypot IP:
    ```
    # TYPE  DATABASE        USER            ADDRESS                 METHOD
    host    honeypot_logs   honeypot_user   192.168.1.50/32         scram-sha-256
    ```
3.  Restart Postgres: `sudo systemctl restart postgresql`

---

## 3. Configuration

Update your `config.yaml` to point to the new backend.

**Using Environment Variables (Recommended):**
Keep your config file clean and pass secrets via `.env`.

**`config.yaml`**:
```yaml
database:
  type: "postgres"
  postgres:
    host: "localhost"
    port: 5432
    dbname: "honeypot_logs"
    user: "honeypot_user"
    password: "" # Will load from ENV: DATABASE_POSTGRES_PASSWORD
```

**`.env`**:
```bash
DATABASE_POSTGRES_PASSWORD=SecurePassword123!
```

---

## 4. Migration Guide (SQLite -> PostgreSQL)

If you have an existing SQLite deployment and want to upgrade without losing data.

### Step 1: Stop the Service
Stops new writes during migration.
```bash
./tools/stop.sh # Or Ctrl+C if running interactively
```

### Step 2: Export Data
Use the export tool to dump your SQLite data to a JSON stream.
```bash
# Ensure config.yaml is still set to 'sqlite' for this step
python3 tools/export_logs.py backup_sqlite.json
```

### Step 3: Switch Configuration
Edit `config.yaml` and set `database.type: "postgres"` (as shown in Section 3).

### Step 4: Import Data
Use the import tool to push the JSON dump into PostgreSQL. The tool automatically detects the active backend from `config.yaml`.

```bash
python3 tools/import_logs.py backup_sqlite.json
```

### Step 5: Restart
```bash
./start.sh
```

**Verification:**
Check the logs to confirm the backend loaded:
```
[INFO] Database Backend Initialized: PostgresBackend (host=localhost)
```
