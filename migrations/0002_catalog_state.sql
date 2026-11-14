-- The reference seeds the catalog generation row in its baseline migration
-- (`0001_executable_catalog.py`: `INSERT INTO public.mcp_catalog_state DEFAULT VALUES`).
-- The SQL baseline port omitted it, so every catalog generation read found no row.

INSERT INTO public.mcp_catalog_state DEFAULT VALUES ON CONFLICT DO NOTHING;
