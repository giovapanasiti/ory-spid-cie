#!/bin/sh
# Creates one database and one least-privilege role per independently managed service.
set -eu
create() {
  db="$1"; user="$2"; pass="$3"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE "$user" LOGIN PASSWORD '$pass';
CREATE DATABASE "$db" OWNER "$user";
REVOKE ALL ON DATABASE "$db" FROM PUBLIC;
SQL
}
create kratos   kratos   "$KRATOS_DB_PASSWORD"
create hydra    hydra    "$HYDRA_DB_PASSWORD"
create federation broker "$BROKER_DB_PASSWORD"
create identity identity "$IDENTITY_DB_PASSWORD"
create audit    audit    "$AUDIT_DB_PASSWORD"
