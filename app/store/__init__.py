"""Data access, one module per area. Only these modules (and db.py for settings, cache and audit) contain SQL for
their tables; everything else calls them. Every change to the configuration bumps config_rev in the same
transaction, so the UI can show that it is not applied yet."""
