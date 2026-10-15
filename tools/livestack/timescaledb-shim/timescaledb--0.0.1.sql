-- No-op stand-ins for the two TimescaleDB functions the go-tangra core
-- migrations call (portal, auth, lcm: internal/store/migrations/0002_hypertables.sql).
CREATE FUNCTION create_hypertable(relation regclass, time_column_name name,
    chunk_time_interval interval DEFAULT NULL, if_not_exists boolean DEFAULT false,
    migrate_data boolean DEFAULT false)
RETURNS TABLE (hypertable_id integer, schema_name name, table_name name, created boolean)
LANGUAGE sql AS $$
  SELECT 0, n.nspname, c.relname, true
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.oid = relation
$$;

CREATE FUNCTION add_retention_policy(relation regclass, drop_after interval,
    if_not_exists boolean DEFAULT false)
RETURNS integer LANGUAGE sql AS $$ SELECT 0 $$;
