# ssh_honeypot/services/mysql/dummy_data.py

# Standard System Variable Responses
SYSTEM_VARIABLES = {
    "@@version": "8.0.35-0ubuntu0.22.04.1",
    "@@version_comment": "(Ubuntu)",
    "@@hostname": "db-prod-01",
    "@@datadir": "/var/lib/mysql/",
    "@@socket": "/var/run/mysqld/mysqld.sock",
    "CURRENT_USER()": "root@localhost",
    "DATABASE()": "production_db",
}

# Dummy Database Schema and Data
# Structure: { "database_name": { "table_name": { "columns": [...], "rows": [...] } } }
DUMMY_DATABASES = {
    "information_schema": {
        "tables": {
            "columns": ["TABLE_SCHEMA", "TABLE_NAME", "TABLE_TYPE"],
            "rows": [
                ("production_db", "users", "BASE TABLE"),
                ("production_db", "products", "BASE TABLE"),
                ("production_db", "orders", "BASE TABLE"),
                ("sys", "metrics", "VIEW"),
            ],
        }
    },
    "production_db": {
        "users": {
            "columns": [
                "id",
                "username",
                "email",
                "password_hash",
                "role",
                "created_at",
            ],
            "rows": [
                (
                    1,
                    "admin",
                    "admin@corp.internal",
                    "5f4dcc3b5aa765d61d8327deb882cf99",
                    "admin",
                    "2023-01-15 10:00:00",
                ),
                (
                    2,
                    "deploy",
                    "deploy@corp.internal",
                    "7c4a8d09ca3762af61e59520943dc26494f8941b",
                    "service",
                    "2023-02-20 14:30:00",
                ),
                (
                    3,
                    "jdoe",
                    "john.doe@corp.internal",
                    "e10adc3949ba59abbe56e057f20f883e",
                    "user",
                    "2023-03-05 09:15:00",
                ),
            ],
        },
        "products": {
            "columns": ["id", "name", "price", "stock", "status"],
            "rows": [
                (101, "API Gateway License", 4999.00, 1000, "active"),
                (102, "Enterprise Support Pack", 15000.00, 50, "active"),
                (103, "Cloud Storage Add-on", 299.00, 5000, "active"),
            ],
        },
    },
}
