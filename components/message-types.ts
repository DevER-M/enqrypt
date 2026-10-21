export type UiMessage = {
  id: string;
  senderId: string;
  sequence: number;
  nonceB64: string;
  ciphertextB64: string;
  createdAt: string;
  streamId: string | null;
  pending?: boolean;
  failed?: boolean;
  localPlaintext?: string;
};

export type DecryptionEntry = {
  plaintext?: string;
  error?: boolean;
};
