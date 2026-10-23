-- Test schema: one tenant-scoped table under row-level security, granted to
-- the application role when it exists (the shape of a module's migrations).
CREATE TABLE items (
  tenant_id uuid NOT NULL,
  id        text NOT NULL,
  name      text NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
ALTER TABLE items FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON items
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid OR current_setting('app.system', true) = 'on')
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid OR current_setting('app.system', true) = 'on');
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'items_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON items TO items_app;
  END IF;
END $$;
