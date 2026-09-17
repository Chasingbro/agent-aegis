CREATE TABLE tenants (id TEXT PRIMARY KEY);
CREATE TABLE accounts (id TEXT PRIMARY KEY, tenant_id TEXT REFERENCES tenants(id), display_name TEXT);
INSERT INTO tenants VALUES ('alpha'), ('beta');
INSERT INTO accounts VALUES ('a-1', 'alpha', 'Synthetic Account A'), ('b-1', 'beta', 'Synthetic Account B');
