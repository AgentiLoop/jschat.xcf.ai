// Port of MultiPeerChatCore/Models.swift (plain JSON objects; dates are ISO-8601 strings)
import { uuid } from './utils.js';

export function User(username, emoji = '👤') {
  return { id: uuid(), username, joinedAt: new Date().toISOString(), emoji };
}

export function Room(name, createdBy) {
  // participants mirrors Swift's Set<User>: every User() has a fresh id, so each insert is unique
  return { id: uuid(), name, createdAt: new Date().toISOString(), participants: [createdBy], createdBy };
}

export const Room_addParticipant = (room, user) => {
  if (!room.participants.some((p) => p.id === user.id)) room.participants.push(user);
};
export const Room_removeParticipant = (room, user) => {
  room.participants = room.participants.filter((p) => p.id !== user.id);
};

export function FileAttachment({ fileName, originalFileName, mimeType, fileSize, filePath, thumbnailPath = null }) {
  return {
    id: uuid(), fileName, originalFileName, mimeType, fileSize, filePath,
    uploadedAt: new Date().toISOString(), isImage: mimeType.startsWith('image/'), thumbnailPath,
  };
}

export const MessageType = { text: 'text', image: 'image', file: 'file', userJoined: 'userJoined', userLeft: 'userLeft', roomCreated: 'roomCreated' };

export function ChatMessage({ content, sender, roomId, messageType = MessageType.text, attachment = null }) {
  return { id: uuid(), content, sender, roomId, timestamp: new Date().toISOString(), messageType, attachment };
}

/** ChatMessage(attachment:sender:roomId:caption:) */
export function FileChatMessage(attachment, sender, roomId, caption = '') {
  return ChatMessage({
    content: caption === '' ? attachment.originalFileName : caption,
    sender, roomId,
    messageType: attachment.isImage ? MessageType.image : MessageType.file,
    attachment,
  });
}

export function ChatLink(room, expiresIn = null) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = crypto.getRandomValues(new Uint32Array(8));
  const inviteCode = Array.from(bytes, (b) => characters[b % characters.length]).join('');
  return {
    roomId: room.id,
    roomName: room.name,
    inviteCode,
    createdBy: room.createdBy,
    expiresAt: expiresIn == null ? null : new Date(Date.now() + expiresIn * 1000).toISOString(),
  };
}

export const ChatLink_isExpired = (link) => link.expiresAt != null && Date.now() > Date.parse(link.expiresAt);
