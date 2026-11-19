// Port of MultiPeerChatCore/FileManager.swift (ChatFileManager) — file bytes live in R2.
import { FileAttachment } from './models.js';
import { pathExtension, uuid } from './utils.js';

export const maxFileSize = 50 * 1024 * 1024; // 50MB

export const allowedImageTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
export const allowedFileTypes = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'text/plain',
  'application/zip',
  'application/x-zip-compressed',
  ...allowedImageTypes,
];

export class FileError extends Error {}
const FILE_ERRORS = {
  fileTooLarge: `File is too large. Maximum size is ${maxFileSize / (1024 * 1024)}MB.`,
  unsupportedFileType: 'File type is not supported.',
  fileNotFound: 'File not found.',
};

function getFileExtension(mimeType, originalFileName) {
  const ext = pathExtension(originalFileName).toLowerCase();
  if (ext) return ext;
  switch (mimeType) {
    case 'image/jpeg': return 'jpg';
    case 'image/png': return 'png';
    case 'image/gif': return 'gif';
    case 'image/webp': return 'webp';
    case 'application/pdf': return 'pdf';
    case 'application/msword': return 'doc';
    case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': return 'docx';
    case 'application/vnd.ms-excel': return 'xls';
    case 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': return 'xlsx';
    case 'application/vnd.ms-powerpoint': return 'ppt';
    case 'application/vnd.openxmlformats-officedocument.presentationml.presentation': return 'pptx';
    case 'text/plain': return 'txt';
    case 'application/zip': case 'application/x-zip-compressed': return 'zip';
    default: return 'bin';
  }
}

export class ChatFileManager {
  constructor(bucket) {
    this.bucket = bucket; // R2 bucket binding
  }

  async saveUploadedFile(data, originalFileName, mimeType) {
    if (!this.bucket) throw new FileError('File uploads are not enabled on this server (R2 bucket not configured).');
    if (data.byteLength > maxFileSize) throw new FileError(FILE_ERRORS.fileTooLarge);
    if (!allowedFileTypes.includes(mimeType)) throw new FileError(FILE_ERRORS.unsupportedFileType);

    const uniqueFileName = `${uuid()}.${getFileExtension(mimeType, originalFileName)}`;
    await this.bucket.put(uniqueFileName, data, { httpMetadata: { contentType: mimeType } });

    // Thumbnails were rendered with AppKit/UIKit; like the Swift build on platforms without
    // those frameworks, no thumbnail is produced and clients display the original image.
    return FileAttachment({
      fileName: uniqueFileName,
      originalFileName,
      mimeType,
      fileSize: data.byteLength,
      filePath: `uploads/${uniqueFileName}`,
      thumbnailPath: null,
    });
  }

  async getFileData(attachment) {
    const obj = this.bucket ? await this.bucket.get(attachment.fileName) : null;
    if (!obj) throw new FileError(FILE_ERRORS.fileNotFound);
    return obj.arrayBuffer();
  }

  async getThumbnailData(attachment) {
    if (!attachment.thumbnailPath || !this.bucket) return null;
    const obj = await this.bucket.get(attachment.thumbnailPath);
    return obj ? obj.arrayBuffer() : null;
  }
}
