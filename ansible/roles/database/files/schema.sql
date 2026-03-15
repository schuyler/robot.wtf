CREATE TABLE IF NOT EXISTS users (
    did TEXT PRIMARY KEY,
    handle TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    username TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL,
    wiki_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wikis (
    slug TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL REFERENCES users(did),
    display_name TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    mcp_token_hash TEXT NOT NULL,
    is_public INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    last_accessed TEXT NOT NULL,
    page_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS acls (
    wiki_slug TEXT NOT NULL REFERENCES wikis(slug),
    grantee_did TEXT NOT NULL REFERENCES users(did),
    role TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (wiki_slug, grantee_did)
);

CREATE TABLE IF NOT EXISTS oauth_sessions (
    id TEXT PRIMARY KEY,
    user_did TEXT NOT NULL REFERENCES users(did),
    dpop_private_jwk TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT,
    redirect_uris TEXT NOT NULL,
    client_secret_hash TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reindex_queue (
    wiki_slug TEXT NOT NULL,
    page_path TEXT NOT NULL,
    action TEXT NOT NULL,
    queued_at TEXT NOT NULL,
    PRIMARY KEY (wiki_slug, page_path)
);
