// Port of PersistenceManager.swift (UserDefaults) + the SwiftData credential store,
// backed by the Durable Object's SQLite database (ctx.storage.sql).

export class Persistence {
  constructor(sql) {
    this.sql = sql;
    sql.exec(`CREATE TABLE IF NOT EXISTS credentials (username TEXT PRIMARY KEY, id TEXT UNIQUE, data TEXT NOT NULL)`);
    sql.exec(`CREATE TABLE IF NOT EXISTS rooms (id TEXT PRIMARY KEY, data TEXT NOT NULL)`);
    sql.exec(`CREATE TABLE IF NOT EXISTS messages (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT, room_id TEXT, data TEXT NOT NULL)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS messages_room ON messages(room_id)`);
    sql.exec(`CREATE TABLE IF NOT EXISTS chat_links (invite_code TEXT PRIMARY KEY, data TEXT NOT NULL)`);
    sql.exec(`CREATE TABLE IF NOT EXISTS attachments (id TEXT PRIMARY KEY, data TEXT NOT NULL)`);
    sql.exec(`CREATE TABLE IF NOT EXISTS admin_sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL)`);
  }

  rows(query, ...args) {
    return this.sql.exec(query, ...args).toArray().map((r) => JSON.parse(r.data));
  }

  // MARK: - WebAuthn credential store (replaces SwiftData WebAuthnCredentialModel)
  get credentialStore() {
    return {
      loadAll: () => this.rows('SELECT data FROM credentials'),
      put: (c) => this.sql.exec(
        'INSERT OR REPLACE INTO credentials (username, id, data) VALUES (?, ?, ?)', c.username, c.id, JSON.stringify(c)),
      delete: (username) => this.sql.exec('DELETE FROM credentials WHERE username = ?', username),
    };
  }

  // MARK: - Admin session store
  get sessionStore() {
    return {
      loadAll: () => this.rows('SELECT data FROM admin_sessions'),
      put: (s) => this.sql.exec('INSERT OR REPLACE INTO admin_sessions (id, data) VALUES (?, ?)', s.sessionId, JSON.stringify(s)),
      delete: (id) => this.sql.exec('DELETE FROM admin_sessions WHERE id = ?', id),
    };
  }

  // MARK: - Room Persistence
  saveRoom(room) {
    this.sql.exec('INSERT OR REPLACE INTO rooms (id, data) VALUES (?, ?)', room.id, JSON.stringify(room));
  }
  loadRooms() { return this.rows('SELECT data FROM rooms ORDER BY rowid'); }
  deleteRoom(roomId) {
    this.sql.exec('DELETE FROM rooms WHERE id = ?', roomId);
    this.clearMessages(roomId);
  }

  // MARK: - Message Persistence
  saveMessage(message) {
    this.sql.exec('INSERT INTO messages (id, room_id, data) VALUES (?, ?, ?)', message.id, message.roomId, JSON.stringify(message));
  }
  loadMessages(roomId) { return this.rows('SELECT data FROM messages WHERE room_id = ? ORDER BY seq', roomId); }
  clearMessages(roomId) { this.sql.exec('DELETE FROM messages WHERE room_id = ?', roomId); }

  // MARK: - Chat Link Persistence
  saveChatLink(link) {
    this.sql.exec('INSERT OR REPLACE INTO chat_links (invite_code, data) VALUES (?, ?)', link.inviteCode, JSON.stringify(link));
  }
  loadChatLinks() { return this.rows('SELECT data FROM chat_links'); }
  deleteChatLink(inviteCode) { this.sql.exec('DELETE FROM chat_links WHERE invite_code = ?', inviteCode); }
  cleanupExpiredLinks(isExpired) {
    for (const link of this.loadChatLinks()) if (isExpired(link)) this.deleteChatLink(link.inviteCode);
  }

  // MARK: - File Attachment Management
  getAllAttachments() {
    const messageAttachments = this.rows('SELECT data FROM messages').map((m) => m.attachment).filter(Boolean);
    return [...messageAttachments, ...this.rows('SELECT data FROM attachments')];
  }
  findAttachment(predicate) { return this.getAllAttachments().find(predicate) ?? null; }
  saveStandaloneAttachment(attachment) {
    this.sql.exec('INSERT OR REPLACE INTO attachments (id, data) VALUES (?, ?)', attachment.id, JSON.stringify(attachment));
  }
}
