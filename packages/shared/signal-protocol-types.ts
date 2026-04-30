/**
 * Signal Protocol encryption provider types and interfaces
 * This file defines the abstraction layer for Signal Protocol implementation
 */

/**
 * Represents the encryption provider interface for Signal Protocol
 * This can be swapped with other encryption providers as needed
 */
export interface EncryptionProvider {
  /**
   * Initialize the encryption provider with required parameters
   */
  initialize(options: EncryptionProviderOptions): Promise<void>

  /**
   * Encrypt message with recipient's public key
   */
  encrypt(
    message: string,
    recipientPublicKey: string,
    senderId: string
  ): Promise<EncryptedMessage>

  /**
   * Decrypt message with private key
   */
  decrypt(
    encryptedMessage: EncryptedMessage,
    senderPublicKey: string
  ): Promise<string>

  /**
   * Generate key pair for user
   */
  generateKeyPair(): Promise<KeyPair>

  /**
   * Get user's public key
   */
  getPublicKey(): Promise<string>

  /**
   * Sign message with private key
   */
  sign(message: string): Promise<string>

  /**
   * Verify signed message
   */
  verify(
    message: string,
    signature: string,
    publicKey: string
  ): Promise<boolean>

  /**
   * Establish double ratchet session with recipient
   */
  establishSession(
    recipientId: string,
    recipientPublicKey: string,
    preKey: PreKeyBundle
  ): Promise<void>

  /**
   * Check if session exists with recipient
   */
  hasSession(recipientId: string): Promise<boolean>

  /**
   * Delete session with recipient
   */
  deleteSession(recipientId: string): Promise<void>

  /**
   * Get current protocol state
   */
  getProtocolState(): Promise<ProtocolState>

  /**
   * Clear all protocol state (logout)
   */
  clearState(): Promise<void>
}

export interface EncryptionProviderOptions {
  accountId: number
  userId: string
  storagePath: string
  logFunction?: (message: string) => void
}

export interface KeyPair {
  publicKey: string
  privateKey: string
}

export interface EncryptedMessage {
  ciphertext: string
  iv: string
  ephemeralPublicKey?: string
  messageNumber?: number
  chainKey?: string
}

export interface PreKeyBundle {
  registrationId: number
  deviceId: number
  preKeyPublic: string
  preKeySigned: string
  preKeySignature: string
  signedPreKeyPublic: string
  identityKey: string
}

export interface ProtocolState {
  userId: string
  deviceId: number
  registrationId: number
  identityKeyPair: KeyPair
  preKeyStore: Record<number, string>
  signedPreKeyStore: Record<number, string>
  sessionStore: Record<string, SessionRecord>
}

export interface SessionRecord {
  recipientId: string
  chainKey: string
  messageNumber: number
  previousChainKey: string
  previousMessageNumber: number
  rootKey: string
  senderChain: SenderChain
  receiverChains: ReceiverChain[]
}

export interface SenderChain {
  chainKey: string
  messageNumber: number
}

export interface ReceiverChain {
  chainKey: string
  messageNumber: number
}

/**
 * Configuration for Signal Protocol
 */
export interface SignalProtocolConfig {
  /**
   * Enable Signal Protocol for new messages
   */
  enabled: boolean

  /**
   * Storage backend type
   */
  storageBackend: 'sqlite' | 'indexeddb' | 'memory'

  /**
   * Maximum message age before sessions reset (in milliseconds)
   * Default: 7 days
   */
  maxSessionAge: number

  /**
   * Enable session key ratcheting
   */
  enableRatcheting: boolean

  /**
   * Pre-key rotation interval (in milliseconds)
   * Default: 24 hours
   */
  preKeyRotationInterval: number

  /**
   * Enable perfect forward secrecy
   */
  enablePFS: boolean
}
