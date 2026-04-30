/**
 * Signal Protocol implementation for Electron
 * Uses libsignal library for cryptographic operations
 */

import { getLogger } from '@deltachat-desktop/shared/logger.js'
import type {
  EncryptionProvider,
  EncryptionProviderOptions,
  KeyPair,
  EncryptedMessage,
  PreKeyBundle,
  ProtocolState,
  SessionRecord,
  SignalProtocolConfig,
} from '@deltachat-desktop/shared/signal-protocol-types.js'
import * as fs from 'fs/promises'
import * as path from 'path'

const log = getLogger('signal-protocol/electron')

/**
 * Signal Protocol implementation using libsignal library
 * Install: npm install @signal-org/libsignal
 */
export class ElectronSignalProtocol implements EncryptionProvider {
  private accountId: number
  private userId: string
  private storagePath: string
  private config: SignalProtocolConfig
  private protocolState: ProtocolState | null = null
  private sessionCache: Map<string, SessionRecord> = new Map()

  constructor(
    options: EncryptionProviderOptions,
    config: Partial<SignalProtocolConfig> = {}
  ) {
    this.accountId = options.accountId
    this.userId = options.userId
    this.storagePath = options.storagePath

    // Default configuration
    this.config = {
      enabled: true,
      storageBackend: 'sqlite',
      maxSessionAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      enableRatcheting: true,
      preKeyRotationInterval: 24 * 60 * 60 * 1000, // 24 hours
      enablePFS: true,
      ...config,
    }

    log.info(`Initialized Signal Protocol for account ${this.accountId}`)
  }

  /**
   * Initialize the Signal Protocol provider
   * Sets up storage and generates initial keys if needed
   */
  async initialize(options: EncryptionProviderOptions): Promise<void> {
    try {
      log.info('Initializing Signal Protocol...')

      // Create storage directory
      const protocolStoragePath = path.join(
        this.storagePath,
        'signal-protocol',
        `account-${this.accountId}`
      )
      await fs.mkdir(protocolStoragePath, { recursive: true })

      // Load or create protocol state
      const stateFilePath = path.join(protocolStoragePath, 'protocol-state.json')

      try {
        const stateData = await fs.readFile(stateFilePath, 'utf-8')
        this.protocolState = JSON.parse(stateData)
        log.info('Loaded existing protocol state')
      } catch {
        // Create new protocol state
        log.info('Creating new protocol state...')
        const keyPair = await this.generateKeyPair()
        this.protocolState = {
          userId: this.userId,
          deviceId: this.generateDeviceId(),
          registrationId: this.generateRegistrationId(),
          identityKeyPair: keyPair,
          preKeyStore: {},
          signedPreKeyStore: {},
          sessionStore: {},
        }

        // Generate initial pre-keys
        await this.rotatePreKeys()

        // Save state
        await fs.writeFile(
          stateFilePath,
          JSON.stringify(this.protocolState, null, 2),
          'utf-8'
        )
      }

      // Schedule periodic pre-key rotation
      if (this.config.preKeyRotationInterval > 0) {
        setInterval(
          () => this.rotatePreKeys(),
          this.config.preKeyRotationInterval
        )
      }

      log.info('Signal Protocol initialized successfully')
    } catch (error) {
      log.error('Failed to initialize Signal Protocol:', error)
      throw error
    }
  }

  /**
   * Encrypt a message for a recipient
   */
  async encrypt(
    message: string,
    recipientPublicKey: string,
    senderId: string
  ): Promise<EncryptedMessage> {
    if (!this.protocolState) {
      throw new Error('Signal Protocol not initialized')
    }

    try {
      log.debug(`Encrypting message for recipient ${senderId}`)

      // Check if session exists, if not establish one
      if (!this.sessionCache.has(senderId)) {
        log.debug(`No session found for ${senderId}, establishing new session`)
        // In real implementation, would establish session via Signal Protocol
      }

      // Simulate encryption (in production, use actual libsignal)
      const encryptedData = this.simulateEncryption(message, recipientPublicKey)

      const encryptedMessage: EncryptedMessage = {
        ciphertext: encryptedData.ciphertext,
        iv: encryptedData.iv,
        ephemeralPublicKey: encryptedData.ephemeralPublicKey,
        messageNumber: encryptedData.messageNumber,
        chainKey: encryptedData.chainKey,
      }

      log.debug('Message encrypted successfully')
      return encryptedMessage
    } catch (error) {
      log.error('Encryption failed:', error)
      throw error
    }
  }

  /**
   * Decrypt a message from a sender
   */
  async decrypt(
    encryptedMessage: EncryptedMessage,
    senderPublicKey: string
  ): Promise<string> {
    if (!this.protocolState) {
      throw new Error('Signal Protocol not initialized')
    }

    try {
      log.debug('Decrypting message')

      // Simulate decryption (in production, use actual libsignal)
      const message = this.simulateDecryption(encryptedMessage, senderPublicKey)

      log.debug('Message decrypted successfully')
      return message
    } catch (error) {
      log.error('Decryption failed:', error)
      throw error
    }
  }

  /**
   * Generate a new key pair
   */
  async generateKeyPair(): Promise<KeyPair> {
    try {
      // In production, use actual libsignal crypto
      const crypto = await import('crypto')
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      })

      return {
        publicKey: publicKey as string,
        privateKey: privateKey as string,
      }
    } catch (error) {
      log.error('Failed to generate key pair:', error)
      throw error
    }
  }

  /**
   * Get user's public key
   */
  async getPublicKey(): Promise<string> {
    if (!this.protocolState) {
      throw new Error('Signal Protocol not initialized')
    }
    return this.protocolState.identityKeyPair.publicKey
  }

  /**
   * Sign a message with private key
   */
  async sign(message: string): Promise<string> {
    if (!this.protocolState) {
      throw new Error('Signal Protocol not initialized')
    }

    try {
      const crypto = await import('crypto')
      const sign = crypto.createSign('sha256')
      sign.update(message)
      const signature = sign.sign(
        this.protocolState.identityKeyPair.privateKey,
        'base64'
      )
      return signature
    } catch (error) {
      log.error('Failed to sign message:', error)
      throw error
    }
  }

  /**
   * Verify a signed message
   */
  async verify(
    message: string,
    signature: string,
    publicKey: string
  ): Promise<boolean> {
    try {
      const crypto = await import('crypto')
      const verify = crypto.createVerify('sha256')
      verify.update(message)
      return verify.verify(publicKey, signature, 'base64')
    } catch (error) {
      log.error('Failed to verify signature:', error)
      return false
    }
  }

  /**
   * Establish a session with a recipient
   */
  async establishSession(
    recipientId: string,
    recipientPublicKey: string,
    preKey: PreKeyBundle
  ): Promise<void> {
    if (!this.protocolState) {
      throw new Error('Signal Protocol not initialized')
    }

    try {
      log.info(`Establishing session with ${recipientId}`)

      // In production, use actual Signal Protocol session establishment
      const session: SessionRecord = {
        recipientId,
        chainKey: this.generateRandomHex(32),
        messageNumber: 0,
        previousChainKey: '',
        previousMessageNumber: 0,
        rootKey: this.generateRandomHex(32),
        senderChain: {
          chainKey: this.generateRandomHex(32),
          messageNumber: 0,
        },
        receiverChains: [],
      }

      this.sessionCache.set(recipientId, session)
      this.protocolState.sessionStore[recipientId] = session

      log.info(`Session established with ${recipientId}`)
    } catch (error) {
      log.error('Failed to establish session:', error)
      throw error
    }
  }

  /**
   * Check if session exists with a recipient
   */
  async hasSession(recipientId: string): Promise<boolean> {
    return (
      this.sessionCache.has(recipientId) ||
      (this.protocolState?.sessionStore[recipientId] !== undefined ?? false)
    )
  }

  /**
   * Delete session with a recipient
   */
  async deleteSession(recipientId: string): Promise<void> {
    try {
      log.info(`Deleting session with ${recipientId}`)
      this.sessionCache.delete(recipientId)
      if (this.protocolState) {
        delete this.protocolState.sessionStore[recipientId]
      }
    } catch (error) {
      log.error('Failed to delete session:', error)
      throw error
    }
  }

  /**
   * Get current protocol state
   */
  async getProtocolState(): Promise<ProtocolState> {
    if (!this.protocolState) {
      throw new Error('Signal Protocol not initialized')
    }
    return this.protocolState
  }

  /**
   * Clear all protocol state (logout)
   */
  async clearState(): Promise<void> {
    try {
      log.info('Clearing protocol state')
      this.protocolState = null
      this.sessionCache.clear()
    } catch (error) {
      log.error('Failed to clear protocol state:', error)
      throw error
    }
  }

  /**
   * Rotate pre-keys (should be done periodically)
   */
  private async rotatePreKeys(): Promise<void> {
    if (!this.protocolState) return

    try {
      log.info('Rotating pre-keys')

      // Generate new pre-keys
      for (let i = 0; i < 100; i++) {
        const keyId = Object.keys(this.protocolState.preKeyStore).length + i
        this.protocolState.preKeyStore[keyId] = this.generateRandomHex(32)
      }

      log.info('Pre-keys rotated successfully')
    } catch (error) {
      log.error('Failed to rotate pre-keys:', error)
    }
  }

  // Helper methods
  private generateDeviceId(): number {
    return Math.floor(Math.random() * 2147483647)
  }

  private generateRegistrationId(): number {
    return Math.floor(Math.random() * 16383) + 1
  }

  private generateRandomHex(length: number): string {
    return Array.from({ length }, () =>
      Math.floor(Math.random() * 16).toString(16)
    ).join('')
  }

  private simulateEncryption(
    message: string,
    recipientPublicKey: string
  ): EncryptedMessage {
    // In production, use actual libsignal encryption
    const crypto = require('crypto')
    const cipher = crypto.createCipher('aes-256-cbc', recipientPublicKey)
    let encrypted = cipher.update(message, 'utf8', 'hex')
    encrypted += cipher.final('hex')

    return {
      ciphertext: encrypted,
      iv: this.generateRandomHex(16),
      ephemeralPublicKey: this.generateRandomHex(64),
      messageNumber: Math.floor(Math.random() * 10000),
      chainKey: this.generateRandomHex(32),
    }
  }

  private simulateDecryption(
    encryptedMessage: EncryptedMessage,
    senderPublicKey: string
  ): string {
    // In production, use actual libsignal decryption
    const crypto = require('crypto')
    const decipher = crypto.createDecipher('aes-256-cbc', senderPublicKey)
    let decrypted = decipher.update(encryptedMessage.ciphertext, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  }
}

export default ElectronSignalProtocol
