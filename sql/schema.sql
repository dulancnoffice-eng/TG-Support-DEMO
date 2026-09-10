CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$ BEGIN
  CREATE TYPE user_role AS ENUM ('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN','AGENT','VIEWER');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE bot_status AS ENUM ('ACTIVE','PAUSED','ERROR');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS workspaces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(120) NOT NULL,
  slug VARCHAR(80) NOT NULL UNIQUE,
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  max_workspace_admins INT NOT NULL DEFAULT 3 CHECK (max_workspace_admins BETWEEN 1 AND 20),
  max_children_per_admin INT NOT NULL DEFAULT 4 CHECK (max_children_per_admin BETWEEN 1 AND 50),
  created_by VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(64) PRIMARY KEY,
  workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
  parent_user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  role user_role NOT NULL,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(190) UNIQUE,
  username VARCHAR(80) UNIQUE,
  password_hash TEXT NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_workspace ON users(workspace_id);
CREATE INDEX IF NOT EXISTS idx_users_parent ON users(parent_user_id);

CREATE TABLE IF NOT EXISTS bots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  platform VARCHAR(30) NOT NULL DEFAULT 'telegram',
  name VARCHAR(120) NOT NULL,
  external_bot_id VARCHAR(120),
  token_ciphertext TEXT NOT NULL,
  token_iv TEXT NOT NULL,
  token_tag TEXT NOT NULL,
  status bot_status NOT NULL DEFAULT 'ACTIVE',
  auto_reply BOOLEAN NOT NULL DEFAULT false,
  created_by VARCHAR(64) NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(workspace_id, platform, external_bot_id)
);

-- Migration-safe fields needed for real Telegram webhook operation.
ALTER TABLE bots ADD COLUMN IF NOT EXISTS external_bot_username VARCHAR(120);
ALTER TABLE bots ADD COLUMN IF NOT EXISTS webhook_secret TEXT;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS webhook_url TEXT;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS webhook_status VARCHAR(20) NOT NULL DEFAULT 'PENDING';
ALTER TABLE bots ADD COLUMN IF NOT EXISTS last_webhook_error TEXT;

CREATE TABLE IF NOT EXISTS bot_assignments (
  bot_id UUID NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
  user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  can_read BOOLEAN NOT NULL DEFAULT true,
  can_reply BOOLEAN NOT NULL DEFAULT true,
  can_manage BOOLEAN NOT NULL DEFAULT false,
  assigned_by VARCHAR(64) NOT NULL REFERENCES users(id),
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(bot_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_bot_assignments_user ON bot_assignments(user_id, bot_id);

CREATE TABLE IF NOT EXISTS customers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  platform VARCHAR(30) NOT NULL,
  external_user_id VARCHAR(160) NOT NULL,
  display_name VARCHAR(160),
  tags TEXT[] NOT NULL DEFAULT '{}',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(workspace_id, platform, external_user_id)
);

CREATE TABLE IF NOT EXISTS conversations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  bot_id UUID REFERENCES bots(id) ON DELETE SET NULL,
  customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  assigned_user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'waiting',
  priority INT NOT NULL DEFAULT 0,
  unread_count INT NOT NULL DEFAULT 0,
  last_message_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_conversations_workspace_status ON conversations(workspace_id, status);
CREATE INDEX IF NOT EXISTS idx_conversations_assigned_user ON conversations(assigned_user_id);
CREATE INDEX IF NOT EXISTS idx_conversations_bot_customer ON conversations(bot_id, customer_id, status);
CREATE INDEX IF NOT EXISTS idx_conversations_last_message ON conversations(workspace_id, last_message_at DESC);

CREATE TABLE IF NOT EXISTS messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_type VARCHAR(20) NOT NULL CHECK (sender_type IN ('customer','agent','bot','system')),
  sender_user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  body TEXT,
  media JSONB,
  external_message_id VARCHAR(160),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation_created ON messages(conversation_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_external_unique
  ON messages(conversation_id, external_message_id)
  WHERE external_message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
  actor_user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(100) NOT NULL,
  entity_type VARCHAR(50),
  entity_id VARCHAR(160),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_workspace_created ON audit_logs(workspace_id, created_at DESC);

-- DLXN17 Customer Support Live V3: one customer thread, reusable tags, remarks, soft deletion, translation cache.
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS remark TEXT;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS remark_updated_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS remark_updated_at TIMESTAMPTZ;

ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS telegram_deleted BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS workspace_tags (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name VARCHAR(40) NOT NULL,
  created_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_workspace_tags_name_ci ON workspace_tags(workspace_id, lower(name));
CREATE INDEX IF NOT EXISTS idx_workspace_tags_workspace ON workspace_tags(workspace_id, name);

CREATE TABLE IF NOT EXISTS message_translations (
  message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  target_language VARCHAR(12) NOT NULL,
  translated_text TEXT NOT NULL,
  detected_source_language VARCHAR(20),
  provider VARCHAR(30) NOT NULL DEFAULT 'google',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(message_id, target_language)
);

CREATE TABLE IF NOT EXISTS system_migrations (
  migration_key VARCHAR(160) PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- DLXN17 Customer Support Live V4: queue lifecycle, dashboard analytics, soft-deleted chat history.
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMPTZ;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS deleted_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS conversation_assignment_events (
  id BIGSERIAL PRIMARY KEY,
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  assigned_user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  assigned_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_assignment_events_workspace_created ON conversation_assignment_events(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assignment_events_user_created ON conversation_assignment_events(assigned_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assignment_events_conversation ON conversation_assignment_events(conversation_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_conversations_deleted_at ON conversations(workspace_id, deleted_at DESC) WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_conversations_resolved_at ON conversations(workspace_id, resolved_at DESC) WHERE resolved_at IS NOT NULL;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS waiting_since TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_conversations_waiting_since ON conversations(workspace_id, waiting_since) WHERE status='waiting';

-- DLXN17 Customer Support V4 Remake: media database, bulk image sets, quick replies, and automation messages.
CREATE TABLE IF NOT EXISTS media_categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  created_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_media_categories_name_ci ON media_categories(workspace_id, lower(name));
CREATE INDEX IF NOT EXISTS idx_media_categories_workspace ON media_categories(workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS media_assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  category_id UUID NOT NULL REFERENCES media_categories(id) ON DELETE CASCADE,
  filename VARCHAR(255) NOT NULL,
  mime_type VARCHAR(120) NOT NULL,
  byte_size INT NOT NULL CHECK (byte_size > 0),
  file_data BYTEA NOT NULL,
  created_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_media_assets_category ON media_assets(category_id, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_media_assets_workspace ON media_assets(workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS quick_replies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  title VARCHAR(80) NOT NULL,
  body TEXT NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_quick_replies_workspace ON quick_replies(workspace_id, sort_order, created_at);

CREATE TABLE IF NOT EXISTS automation_messages (
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  trigger_type VARCHAR(30) NOT NULL CHECK (trigger_type IN ('new_customer','assigned')),
  enabled BOOLEAN NOT NULL DEFAULT false,
  body TEXT NOT NULL DEFAULT '',
  updated_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(workspace_id, trigger_type)
);
