// Durable Object that is the 1:1 port of the Swift ChatServer process:
//   WebServer.swift      → HTTP routing, admin API, uploads, icons, WebSocket upgrade
//   WebChatServer.swift  → chat protocol (rooms, messages, invites, emojis)
// One global instance holds all state, like the single Swift process did.
import { DurableObject } from 'cloudflare:workers';
import { WebAuthnManager } from './webauthn/manager.js';
import { WebAuthnServer } from './webauthn/server.js';
import { WebAuthAdminManager, AdminManager } from './admin-manager.js';
import { Persistence } from './persistence.js';
import { ChatFileManager } from './file-manager.js';
import {
  User, Room, Room_addParticipant, Room_removeParticipant, ChatMessage, FileChatMessage, ChatLink, ChatLink_isExpired,
} from './models.js';
import * as icons from './icons.js';
import * as admin from './admin-content.js';
import { analyzeEmojiColors } from './emoji-colors.js';
import {
  textResponse, jsonResponse, errorResponse, binaryResponse, extractClientIP, iso8601, pathExtension,
} from './utils.js';

const ICON_CACHE = { 'Cache-Control': 'public, max-age=31536000' };
const ADMIN_USER_PATH = /\/admin\/api\/users\/[^/]+/;

export class ChatServer extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.rpId = env.RP_ID || 'jschat.xcf.ai';
    this.adminUsername = env.ADMIN_USERNAME || 'XCF Admin';

    // WebChatServer state
    this.clients = new Set();     // WebServer.clients (every socket)
    this.rooms = new Map();       // roomId -> Room
    this.users = new Map();       // username -> client
    this.userRooms = new Map();   // username -> roomId
    this.inviteLinks = new Map(); // inviteCode -> ChatLink
    this.roomMessages = new Map();// roomId -> [ChatMessage]
    this.userEmojis = new Map();  // username -> emoji

    this.persistence = new Persistence(ctx.storage.sql);
    this.fileManager = new ChatFileManager(env.UPLOADS);

    // WebServer.init
    const iconUrl = this.rpId.toLowerCase() === 'localhost'
      ? `http://localhost:${env.LOCAL_PORT || 8787}/icon-192.png`
      : 'https://ui-avatars.com/api/?name=💬Chat&background=007AFF&color=white&size=192&format=png';
    this.webAuthnManager = new WebAuthnManager({
      rpId: this.rpId,
      store: this.persistence.credentialStore,
      rpName: 'Multi-Peer Chat',
      rpIcon: iconUrl,
      defaultUserIcon: null,
      adminUsername: this.adminUsername,
    });
    this.webAuthnServer = new WebAuthnServer(this.webAuthnManager);
    this.adminManager = new AdminManager(this.adminUsername, this.persistence.sessionStore);
    this.webAuthAdminManager = new WebAuthAdminManager(this.webAuthnManager, this.adminUsername);
    this.adminManager.delegate = {
      didAuthenticateUser: (u) => this.webAuthAdminManager.verifyAdminAccess(u),
      shouldAllowAdminAccess: (u) => this.webAuthAdminManager.shouldAllowAdminAccess(u),
    };
    this.webAuthAdminManager.bootstrapAdminUser();

    // WebChatServer.init
    this.loadPersistedData();
    if (![...this.rooms.values()].some((r) => r.name === 'Lobby')) {
      const lobbyRoom = Room('Lobby', User('System'));
      this.rooms.set(lobbyRoom.id, lobbyRoom);
      this.roomMessages.set(lobbyRoom.id, []);
      this.persistence.saveRoom(lobbyRoom);
    }
  }

  loadPersistedData() {
    const persistedRooms = this.persistence.loadRooms();
    for (const room of persistedRooms) this.rooms.set(room.id, room);
    for (const link of this.persistence.loadChatLinks()) {
      if (!ChatLink_isExpired(link)) this.inviteLinks.set(link.inviteCode, link);
    }
    for (const room of persistedRooms) this.roomMessages.set(room.id, this.persistence.loadMessages(room.id));
    this.persistence.cleanupExpiredLinks(ChatLink_isExpired);
  }

  // MARK: - HTTP (WebServer.handleHTTPRequest)

  async fetch(request) {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;
    this.adminManager.cleanupExpiredSessions(); // replaces the 15-minute cleanup timer

    if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
      return this.handleWebSocketUpgrade();
    }

    // Any multipart POST is treated as an upload, like WebServer.handleNewConnection
    if (method === 'POST' && (path === '/upload' || (request.headers.get('content-type') || '').toLowerCase().includes('multipart/form-data'))) {
      return this.handleFileUpload(request);
    }

    const session = () => this.adminManager.isValidAdminSession(request) || this.adminManager.hasValidAdminSession(request);
    const notFound = () => textResponse('404 Not Found', 'text/plain', 404);

    if (method === 'GET') {
      switch (path) {
        case '/admin/index.html': case '/admin/': case '/admin':
        case '/admin/login.html':
          return textResponse(admin.generateAdminLoginHTML, 'text/html');
        case '/admin/panel.html':
          return this.adminManager.isValidAdminSession(request)
            ? textResponse(admin.generateAdminIndexHTML, 'text/html') : notFound();
        case '/admin/admin.css':
          return textResponse(admin.generateAdminCSS, 'text/css');
        case '/admin/admin.js':
          return this.adminManager.isValidAdminSession(request)
            ? textResponse(admin.generateAdminJS, 'application/javascript')
            : textResponse('401 Unauthorized', 'text/plain', 401);
        case '/admin/admin-login.js':
          return textResponse(admin.generateAdminLoginJS, 'application/javascript');
        case '/admin/api/users':
          return session() ? jsonResponse(this.webAuthAdminManager.getAllUsers())
            : textResponse('401 Unauthorized', 'text/plain', 401);
        case '/manifest.json':
          return textResponse(icons.generateWebManifest(), 'application/json');
        case '/browserconfig.xml':
          return textResponse(icons.generateBrowserConfig(), 'application/xml');
        case '/favicon.ico':
          return binaryResponse(icons.generateSimpleFaviconSVG(), 'image/svg+xml', ICON_CACHE);
        case '/favicon.png':
          return binaryResponse(icons.generateSimplePNGFavicon(), 'image/png', ICON_CACHE);
        case '/chat-preview.png':
          return textResponse(icons.generatePreviewImageSVG(), 'image/svg+xml');
      }
      if ((path.startsWith('/favicon-') && path.endsWith('.png')) || (path.startsWith('/icons/favicon-') && path.endsWith('.png'))) {
        return binaryResponse(icons.generateMacOSFaviconSVG(icons.faviconSizeFromPath(path)), 'image/svg+xml', ICON_CACHE);
      }
      const iconMatch = path.match(/^\/icon-(192|512|180|152|144|120|114|96|72|64|60|57|48|32)\.png$/);
      if (iconMatch) return binaryResponse(icons.generateAppIconPNG(+iconMatch[1]), 'image/svg+xml', ICON_CACHE);
      if (path.startsWith('/icons/')) {
        return binaryResponse(icons.generateAppleAppIconData(icons.appleIconSizeFromPath(path)), 'image/png', ICON_CACHE);
      }
      if (path.startsWith('/files/')) return this.handleFileServing(path);
      if (path.startsWith('/thumbnails/')) return this.handleThumbnailServing(path);
      return notFound();
    }

    if (method === 'POST') {
      if (path === '/admin/api/login') return this.handleAdminLogin(request);
      if (/\/admin\/api\/users\/[^/]+\/toggle/.test(path)) {
        return session() ? this.handleAdminAPIToggleUser(request, path) : notFound();
      }
      if (path === '/admin/api/users/disable-by-ip') {
        return session() ? this.handleAdminAPIDisableByIP(request) : notFound();
      }
      if (/\/admin\/api\/users\/[^/]+\/emoji/.test(path)) {
        return session() ? this.handleAdminAPIUpdateEmoji(request, path) : notFound();
      }
      if (/\/admin\/api\/users\/[^/]+\/admin/.test(path)) {
        return session() ? this.handleAdminAPIToggleAdmin(request, path) : notFound();
      }
      if (path.startsWith('/webauthn/')) return this.webAuthnServer.handleRequest(request);
      if (path === '/emoji/analyze') return this.handleEmojiColorAnalysis(request);
      return notFound();
    }

    if (method === 'DELETE' && ADMIN_USER_PATH.test(path)) {
      return session() ? this.handleAdminAPIDeleteUser(path) : notFound();
    }

    return notFound();
  }

  // MARK: - Emoji colours

  async handleEmojiColorAnalysis(request) {
    let emoji;
    try { emoji = (await request.json()).emoji; } catch { /* fallthrough */ }
    if (typeof emoji !== 'string') return errorResponse('Invalid request body or missing emoji');
    try {
      const colors = await analyzeEmojiColors(emoji);
      return jsonResponse({ success: true, emoji, ...colors });
    } catch (error) {
      return errorResponse(`Failed to analyze emoji colors: ${error.message}`);
    }
  }

  // MARK: - Uploads (handleFileUploadBinary / processBinaryUpload)

  async handleFileUpload(request) {
    const contentType = (request.headers.get('content-type') || '').toLowerCase();
    if (!contentType.includes('multipart/form-data')) {
      // handleFileUploadSimple
      const body = await request.text();
      return jsonResponse({ success: true, message: 'Upload endpoint reached successfully', requestLength: body.length });
    }
    if (!contentType.includes('boundary=')) return errorResponse('Missing boundary');

    let file = null;
    try {
      const form = await request.formData();
      for (const [, value] of form.entries()) {
        if (typeof value === 'object' && value !== null && 'arrayBuffer' in value) { file = value; break; }
      }
    } catch {
      return errorResponse('Invalid multipart format');
    }

    const originalName = file?.name;
    let mime = file?.type;
    if (!mime && originalName) {
      switch (pathExtension(originalName).toLowerCase()) {
        case 'png': mime = 'image/png'; break;
        case 'jpg': case 'jpeg': mime = 'image/jpeg'; break;
        case 'gif': mime = 'image/gif'; break;
        case 'pdf': mime = 'application/pdf'; break;
        case 'txt': mime = 'text/plain'; break;
        case 'zip': mime = 'application/zip'; break;
        default: mime = 'application/octet-stream';
      }
    }
    const fileData = file ? await file.arrayBuffer() : null;
    if (!originalName || !mime || !fileData || fileData.byteLength === 0) {
      return errorResponse('Missing required file data');
    }

    try {
      const attachment = await this.fileManager.saveUploadedFile(fileData, originalName, mime);
      this.persistence.saveStandaloneAttachment(attachment);
      const attachmentResponse = {
        id: attachment.id,
        fileName: attachment.fileName,
        originalFileName: attachment.originalFileName,
        name: attachment.originalFileName,
        mimeType: attachment.mimeType,
        fileSize: attachment.fileSize,
        size: attachment.fileSize,
        url: `/files/${attachment.id}/${attachment.originalFileName}`,
        isImage: attachment.isImage,
      };
      if (attachment.thumbnailPath) attachmentResponse.thumbnailUrl = `/${attachment.thumbnailPath}`;
      return jsonResponse({ success: true, attachment: attachmentResponse });
    } catch (error) {
      return errorResponse(`Failed to save file: ${error.message}`);
    }
  }

  async handleFileServing(path) {
    const parts = path.split('/').filter(Boolean).map((p) => decodeURIComponent(p));
    let attachment = null;
    if (parts.length === 2) attachment = this.persistence.findAttachment((a) => a.fileName === parts[1]);
    else if (parts.length === 3) attachment = this.persistence.findAttachment((a) => a.id === parts[1]);
    if (!attachment) return errorResponse('File not found', 404);
    try {
      const data = await this.fileManager.getFileData(attachment);
      return binaryResponse(data, attachment.mimeType, {
        'Content-Disposition': `inline; filename="${attachment.originalFileName}"`,
      });
    } catch {
      return errorResponse('Failed to read file', 500);
    }
  }

  async handleThumbnailServing(path) {
    const thumbnailPath = decodeURIComponent(path.slice(1));
    const attachment = this.persistence.findAttachment((a) => a.thumbnailPath === thumbnailPath);
    if (!attachment) return errorResponse('Thumbnail not found', 404);
    const data = await this.fileManager.getThumbnailData(attachment);
    if (!data) return errorResponse('Thumbnail not available', 404);
    return binaryResponse(data, 'image/jpeg', { 'Content-Disposition': 'inline; filename="thumbnail.jpg"' });
  }

  // MARK: - Admin API

  credentialIdFromPath(path) {
    const raw = path.split('/')[4];
    try { return decodeURIComponent(raw); } catch { return null; }
  }

  async readJSON(request) {
    try { return await request.json(); } catch { return null; }
  }

  async handleAdminAPIToggleUser(request, path) {
    const credentialId = this.credentialIdFromPath(path);
    if (credentialId == null) return errorResponse('Invalid credential ID encoding');
    const body = await this.readJSON(request);
    if (typeof body?.enabled !== 'boolean') return errorResponse('Invalid request body');
    return this.webAuthAdminManager.toggleUserStatus(credentialId, body.enabled)
      ? jsonResponse({ success: true, message: 'User status updated successfully' })
      : errorResponse('Failed to update user status');
  }

  handleAdminAPIDeleteUser(path) {
    const credentialId = this.credentialIdFromPath(path);
    if (credentialId == null) return errorResponse('Invalid credential ID encoding');
    return this.webAuthAdminManager.deleteUser(credentialId)
      ? jsonResponse({ success: true }) : errorResponse('Failed to delete user');
  }

  async handleAdminAPIDisableByIP(request) {
    const body = await this.readJSON(request);
    if (typeof body?.ipAddress !== 'string') return errorResponse('Invalid request body');
    return jsonResponse({ success: true, disabledCount: this.webAuthAdminManager.disableUsersByIP(body.ipAddress) });
  }

  async handleAdminAPIUpdateEmoji(request, path) {
    const body = await this.readJSON(request);
    if (typeof body?.emoji !== 'string') return jsonResponse({ error: 'Invalid request data' }, 400);
    const credentialId = this.credentialIdFromPath(path);
    if (credentialId == null) return jsonResponse({ error: 'Invalid credential ID encoding' }, 400);
    return this.webAuthAdminManager.updateUserEmoji(credentialId, body.emoji)
      ? jsonResponse({ success: true, message: 'Emoji updated successfully' })
      : jsonResponse({ error: 'Failed to update emoji' }, 500);
  }

  async handleAdminAPIToggleAdmin(request, path) {
    const body = await this.readJSON(request);
    if (typeof body?.isAdmin !== 'boolean') return jsonResponse({ error: 'Invalid request data' }, 400);
    const credentialId = this.credentialIdFromPath(path);
    if (credentialId == null) return jsonResponse({ error: 'Invalid credential ID encoding' }, 400);
    return this.webAuthAdminManager.toggleUserAdminStatus(credentialId, body.isAdmin)
      ? jsonResponse({ success: true, message: 'Admin role updated successfully' })
      : jsonResponse({ error: 'Failed to update admin role' }, 500);
  }

  async handleAdminLogin(request) {
    const clientIP = extractClientIP(request);
    const json = await this.readJSON(request);
    if (typeof json?.username !== 'string') return errorResponse('Invalid request body');

    let finalUsername;
    try {
      finalUsername = await this.webAuthAdminManager.authenticateAdmin(json.username, json, clientIP);
    } catch {
      return errorResponse('Authentication failed', 401);
    }
    if (!finalUsername) return errorResponse('Authentication failed', 401);
    if (!this.webAuthAdminManager.verifyAdminAccess(finalUsername)) return errorResponse('Access denied', 403);

    const { sessionId, success } = this.adminManager.createAdminSession(finalUsername, clientIP);
    if (!success) return errorResponse('Session creation failed', 500);

    return jsonResponse({ success: true, sessionId, username: finalUsername }, 200, {
      'Set-Cookie': `adminSessionId=${sessionId}; HttpOnly; SameSite=Strict; Path=/admin`,
    });
  }

  // MARK: - WebSocket (WebServer.handleWebSocketUpgrade + WebSocketClient)

  handleWebSocketUpgrade() {
    const pair = new WebSocketPair();
    const [clientSocket, ws] = Object.values(pair);
    ws.accept();

    const client = {
      ws,
      username: null,
      currentRoom: null,
      send(message) { try { ws.send(message); } catch { /* socket closed */ } },
    };
    this.clients.add(client);

    ws.addEventListener('message', (event) => {
      if (typeof event.data === 'string') this.didReceiveMessage(event.data, client);
    });
    let disconnected = false;
    const onDisconnect = () => {
      if (disconnected) return;
      disconnected = true;
      this.clients.delete(client);
      this.clientDidDisconnect(client);
    };
    ws.addEventListener('close', onDisconnect);
    ws.addEventListener('error', onDisconnect);

    return new Response(null, { status: 101, webSocket: clientSocket });
  }

  broadcastRaw(message) {
    for (const client of this.clients) client.send(message);
  }

  // MARK: - WebServerDelegate (WebChatServer)

  didReceiveMessage(message, client) {
    let json;
    try { json = JSON.parse(message); } catch { return; }
    if (!json || typeof json.type !== 'string') return;

    switch (json.type) {
      case 'join': return this.handleUserJoin(json, client);
      case 'createRoom': return this.handleCreateRoom(json, client);
      case 'joinRoom': return this.handleJoinRoom(json, client);
      case 'leaveRoom': return this.handleLeaveRoom(json, client);
      case 'sendMessage': return this.handleSendMessage(json, client);
      case 'sendFileMessage': return this.handleSendFileMessage(json, client);
      case 'createInvite': return this.handleCreateInvite(json, client);
      case 'clearChatHistory': return this.handleClearChatHistory(json, client);
      case 'removeRoom': return this.handleRemoveRoom(json, client);
      case 'ping': return this.sendToClient(client, { type: 'pong' });
      case 'pong': return undefined; // client is healthy
      case 'updateEmoji': return this.handleUpdateEmoji(json, client);
      default: return undefined;
    }
  }

  clientDidDisconnect(client) {
    const username = client.username;
    if (username) {
      this.users.delete(username);
      const roomId = this.userRooms.get(username);
      if (roomId !== undefined) {
        this.leaveUserFromRoom(username, roomId);
        this.userRooms.delete(username);
      }
    }
    this.broadcastUserCount();
  }

  // MARK: - Message Handlers

  handleUserJoin(json, client) {
    const username = json.username;
    if (typeof username !== 'string') return;
    const emoji = typeof json.emoji === 'string' ? json.emoji : '👤';
    const isReconnecting = json.isReconnecting === true;

    client.username = username;

    const storedEmoji = this.webAuthnManager.getUserEmoji(username) ?? emoji;
    this.userEmojis.set(username, storedEmoji);
    if (emoji !== '👤' && emoji !== storedEmoji) {
      this.webAuthnManager.updateUserEmoji(username, emoji);
      this.userEmojis.set(username, emoji);
    }

    this.users.set(username, client);

    this.sendToClient(client, {
      type: 'roomList',
      rooms: [...this.rooms.values()].map((r) => this.roomToDict(r)),
      isAdmin: username === this.adminUsername,
      userEmoji: this.userEmojis.get(username) ?? '👤',
    });

    if (!isReconnecting) {
      const lobby = [...this.rooms.values()].find((r) => r.name === 'Lobby');
      if (lobby) this.handleJoinRoom({ roomId: lobby.id }, client);
    }

    this.broadcastUserCount();
  }

  handleCreateRoom(json, client) {
    const roomName = json.name;
    const username = client.username;
    if (typeof roomName !== 'string' || !username) return;

    const duplicate = [...this.rooms.values()].find((r) => r.name.toLowerCase() === roomName.toLowerCase());
    if (duplicate || roomName.toLowerCase() === 'lobby') {
      this.sendToClient(client, { type: 'error', message: 'A room with this name already exists' });
      return;
    }

    const room = Room(roomName, User(username));
    this.rooms.set(room.id, room);
    this.roomMessages.set(room.id, []);
    this.persistence.saveRoom(room);

    this.broadcast({ type: 'roomCreated', room: this.roomToDict(room) });
  }

  attachmentDict(attachment) {
    const dict = {
      id: attachment.id,
      fileName: attachment.fileName,
      originalFileName: attachment.originalFileName,
      name: attachment.originalFileName,
      mimeType: attachment.mimeType,
      fileSize: attachment.fileSize,
      size: attachment.fileSize,
      url: `/files/${attachment.id}/${attachment.originalFileName}`,
      isImage: attachment.isImage,
      filePath: attachment.filePath,
      thumbnailPath: attachment.thumbnailPath ?? null,
    };
    if (attachment.thumbnailPath) dict.thumbnailUrl = `/${attachment.thumbnailPath}`;
    return dict;
  }

  handleJoinRoom(json, client) {
    const roomId = json.roomId;
    const username = client.username;
    const room = typeof roomId === 'string' ? this.rooms.get(roomId) : undefined;
    if (!username || !room) return;

    const currentRoomId = this.userRooms.get(username);
    if (currentRoomId !== undefined) this.leaveUserFromRoom(username, currentRoomId);

    Room_addParticipant(room, User(username));
    this.userRooms.set(username, roomId);
    client.currentRoom = roomId;

    for (const message of this.roomMessages.get(roomId) ?? []) {
      const payload = {
        sender: message.sender.username,
        content: message.content,
        timestamp: iso8601(new Date(message.timestamp)),
        messageType: message.messageType,
        emoji: message.sender.emoji,
      };
      if (message.attachment) payload.attachment = this.attachmentDict(message.attachment);
      this.sendToClient(client, { type: 'chatMessage', message: payload });
    }

    this.sendToClient(client, { type: 'roomJoined', room: this.roomToDict(room), isAdmin: username === this.adminUsername });
  }

  handleLeaveRoom(json, client) {
    const roomId = json.roomId;
    const username = client.username;
    if (typeof roomId !== 'string' || !username) return;
    this.leaveUserFromRoom(username, roomId);
    this.userRooms.delete(username);
    client.currentRoom = null;
  }

  handleSendMessage(json, client) {
    const { roomId, content } = json;
    const username = client.username;
    const room = typeof roomId === 'string' ? this.rooms.get(roomId) : undefined;
    if (typeof content !== 'string' || !username || !room) return;

    const storedEmoji = this.userEmojis.get(username) ?? this.webAuthnManager.getUserEmoji(username);
    const providedEmoji = typeof json.emoji === 'string' ? json.emoji : null;
    const emoji = storedEmoji ?? providedEmoji ?? '👤';

    if (providedEmoji !== null && providedEmoji !== emoji) {
      this.webAuthnManager.updateUserEmoji(username, providedEmoji);
      this.userEmojis.set(username, providedEmoji);
    }

    const chatMessage = ChatMessage({ content, sender: User(username, emoji), roomId: room.id });
    this.persistence.saveMessage(chatMessage);
    if (!this.roomMessages.has(roomId)) this.roomMessages.set(roomId, []);
    this.roomMessages.get(roomId).push(chatMessage);

    this.broadcastToRoom(roomId, {
      type: 'chatMessage',
      message: {
        sender: username,
        content,
        timestamp: iso8601(new Date(chatMessage.timestamp)),
        messageType: chatMessage.messageType,
        emoji,
      },
    });
  }

  handleSendFileMessage(json, client) {
    const roomId = json.roomId;
    const username = client.username;
    const room = typeof roomId === 'string' ? this.rooms.get(roomId) : undefined;
    const attachmentId = json.attachment?.id;
    if (!username || !room || typeof attachmentId !== 'string') return;

    const attachment = this.persistence.findAttachment((a) => a.id.toUpperCase() === attachmentId.toUpperCase());
    if (!attachment) {
      console.log(`❌ Attachment not found: ${attachmentId}`);
      return;
    }

    const caption = typeof json.caption === 'string' ? json.caption : '';
    const emoji = this.userEmojis.get(username) ?? '👤';
    const chatMessage = FileChatMessage(attachment, User(username, emoji), room.id, caption);

    this.persistence.saveMessage(chatMessage);
    if (!this.roomMessages.has(roomId)) this.roomMessages.set(roomId, []);
    this.roomMessages.get(roomId).push(chatMessage);

    this.broadcastToRoom(roomId, {
      type: 'chatMessage',
      message: {
        sender: username,
        content: chatMessage.content,
        timestamp: iso8601(new Date(chatMessage.timestamp)),
        messageType: chatMessage.messageType,
        emoji,
        attachment: this.attachmentDict(attachment),
      },
    });
  }

  handleCreateInvite(json, client) {
    const room = typeof json.roomId === 'string' ? this.rooms.get(json.roomId) : undefined;
    if (!room) return;
    const link = ChatLink(room, 3600); // 1 hour
    this.inviteLinks.set(link.inviteCode, link);
    this.persistence.saveChatLink(link);
    this.sendToClient(client, { type: 'inviteCreated', link: `http://${this.rpId}/join/${link.inviteCode}` });
  }

  handleClearChatHistory(json, client) {
    if (client.username !== this.adminUsername) {
      this.sendToClient(client, { type: 'error', message: 'Only an admin can clear history.' });
      return;
    }
    const roomId = json.roomId;
    if (typeof roomId !== 'string' || !/^[0-9A-F-]{36}$/i.test(roomId)) return;
    this.persistence.clearMessages(roomId);
    this.roomMessages.delete(roomId);
    this.broadcastToRoom(roomId, { type: 'chatHistoryCleared', roomId });
  }

  handleRemoveRoom(json, client) {
    if (client.username !== this.adminUsername) {
      this.sendToClient(client, { type: 'error', message: 'Only an admin can remove rooms.' });
      return;
    }
    const roomId = json.roomId;
    const room = typeof roomId === 'string' ? this.rooms.get(roomId) : undefined;
    if (!room || room.name.toLowerCase() === 'lobby') return;
    this.rooms.delete(roomId);
    this.roomMessages.delete(roomId);
    this.persistence.deleteRoom(room.id);
    this.broadcast({ type: 'roomRemoved', roomId });
  }

  handleUpdateEmoji(json, client) {
    const username = client.username;
    const newEmoji = json.emoji;
    if (!username || typeof newEmoji !== 'string') return;
    if (this.webAuthnManager.updateUserEmoji(username, newEmoji)) {
      this.userEmojis.set(username, newEmoji);
      this.sendToClient(client, { type: 'emojiUpdated', emoji: newEmoji, success: true });
    } else {
      this.sendToClient(client, { type: 'emojiUpdated', success: false, error: 'Failed to update emoji' });
    }
  }

  // MARK: - Helper Methods

  leaveUserFromRoom(username, roomId) {
    const room = this.rooms.get(roomId);
    if (room) Room_removeParticipant(room, User(username));
  }

  broadcastToRoom(roomId, message, excludeUser = null) {
    const messageString = JSON.stringify(message);
    for (const [username, client] of this.users) {
      if (this.userRooms.get(username) === roomId && username !== excludeUser) client.send(messageString);
    }
  }

  broadcast(message) { this.broadcastRaw(JSON.stringify(message)); }

  sendToClient(client, message) { client.send(JSON.stringify(message)); }

  broadcastUserCount() { this.broadcast({ type: 'userCount', count: this.users.size }); }

  roomToDict(room) {
    return {
      id: room.id,
      name: room.name,
      createdAt: iso8601(new Date(room.createdAt)),
      participantCount: room.participants.length,
      createdBy: room.createdBy.username,
    };
  }
}
