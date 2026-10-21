import { bytesToBase64 } from './encoding';
import type { MessageRow, SessionRow } from './db/schema';

export type MessageDto = {
  id: string;
  conversation_id: string;
  sender_id: string;
  sequence: number;
  nonce_b64: string;
  ciphertext_b64: string;
  created_at: string;
};

export function toMessageDto(row: MessageRow): MessageDto {
  return {
    id: row.id,
    conversation_id: row.conversationId,
    sender_id: row.senderId,
    sequence: Number(row.sequence),
    nonce_b64: bytesToBase64(row.nonce),
    ciphertext_b64: bytesToBase64(row.ciphertext),
    created_at:
      row.createdAt instanceof Date ? row.createdAt.toISOString() : String(row.createdAt),
  };
}

export type SessionDto = {
  session_id: string;
  conversation_id: string;
  initiator_id: string;
  kem_ciphertext_b64: string;
  created_at: string;
};

export function toSessionDto(row: SessionRow): SessionDto {
  return {
    session_id: row.id,
    conversation_id: row.conversationId,
    initiator_id: row.initiatorId,
    kem_ciphertext_b64: bytesToBase64(row.kemCiphertext),
    created_at: row.createdAt instanceof Date ? row.createdAt.toISOString() : String(row.createdAt),
  };
}
