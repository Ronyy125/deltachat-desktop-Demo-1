/**
 * Integration module for Signal Protocol with DeltaChat IPC
 * Handles message encryption/decryption at the IPC boundary
 */

import { ipcMain } from 'electron'
import { getLogger } from '@deltachat-desktop/shared/logger.js'
import ElectronSignalProtocol from './signal-protocol.js'
import type {
  EncryptedMessage,
  PreKeyBundle,
  SignalProtocolConfig,
} from '@deltachat-desktop/shared/signal-protocol-types.js'

const log = getLogger('signal-protocol/ipc-integration')

/**
 * Singleton instance per account
 */
const signalProtocolInstances = new Map<
  number,
  ElectronSignalProtocol
>()

/**
 * Initialize Signal Protocol for an account
 */
export async function initializeSignalProtocol(
  accountId: number,
  userId: string,
  storagePath: string,
  config?: Partial<SignalProtocolConfig>
): Promise<void> {
  try {
    log.info(`Initializing Signal Protocol for account ${accountId}`)

    const signalProtocol = new ElectronSignalProtocol(
      {
        accountId,
        userId,
        storagePath,
      },
      config
    )

    await signalProtocol.initialize({
      accountId,
      userId,
      storagePath,
    })

    signalProtocolInstances.set(accountId, signalProtocol)
  } catch (error) {
    log.error(
      `Failed to initialize Signal Protocol for account ${accountId}:`,
      error
    )
    throw error
  }
}

/**
 * Get Signal Protocol instance for account
 */
function getSignalProtocol(accountId: number): ElectronSignalProtocol {
  const protocol = signalProtocolInstances.get(accountId)
  if (!protocol) {
    throw new Error(
      `Signal Protocol not initialized for account ${accountId}`
    )
  }
  return protocol
}

/**
 * Setup IPC handlers for Signal Protocol
 */
export function setupSignalProtocolIPC(): void {
  log.info('Setting up Signal Protocol IPC handlers')

  /**
   * Encrypt message handler
   */
  ipcMain.handle(
    'signal-protocol:encrypt',
    async (
      _ev,
      accountId: number,
      message: string,
      recipientPublicKey: string,
      senderId: string
    ) => {
      try {
        const protocol = getSignalProtocol(accountId)
        const encrypted = await protocol.encrypt(
          message,
          recipientPublicKey,
          senderId
        )
        return { success: true, data: encrypted }
      } catch (error) {
        log.error('IPC encrypt failed:', error)
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        }
      }
    }
  )

  /**
   * Decrypt message handler
   */
  ipcMain.handle(
    'signal-protocol:decrypt',
    async (
      _ev,
      accountId: number,
      encryptedMessage: EncryptedMessage,
      senderPublicKey: string
    ) => {
      try {
        const protocol = getSignalProtocol(accountId)
        const decrypted = await protocol.decrypt(encryptedMessage, senderPublicKey)
        return { success: true, data: decrypted }
      } catch (error) {
        log.error('IPC decrypt failed:', error)
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        }
      }
    }
  )

  /**
   * Generate key pair handler
   */
  ipcMain.handle(
    'signal-protocol:generateKeyPair',
    async (_ev, accountId: number) => {
      try {
        const protocol = getSignalProtocol(accountId)
        const keyPair = await protocol.generateKeyPair()
        return { success: true, data: keyPair }
      } catch (error) {
        log.error('IPC generateKeyPair failed:', error)
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        }
      }
    }
  )

  /**
   * Get public key handler
   */
  ipcMain.handle(
    'signal-protocol:getPublicKey',
    async (_ev, accountId: number) => {
      try {
        const protocol = getSignalProtocol(accountId)
        const publicKey = await protocol.getPublicKey()
        return { success: true, data: publicKey }
      } catch (error) {
        log.error('IPC getPublicKey failed:', error)
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        }
      }
    }
  )

  /**
   * Sign message handler
   */
  ipcMain.handle(
    'signal-protocol:sign',
    async (_ev, accountId: number, message: string) => {
      try {
        const protocol = getSignalProtocol(accountId)
        const signature = await protocol.sign(message)
        return { success: true, data: signature }
      } catch (error) {
        log.error('IPC sign failed:', error)
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        }
      }
    }
  )

  /**
   * Verify signature handler
   */
  ipcMain.handle(
    'signal-protocol:verify',
    async (
      _ev,
      accountId: number,
      message: string,
      signature: string,
      publicKey: string
    ) => {
      try {
        const protocol = getSignalProtocol(accountId)
        const isValid = await protocol.verify(message, signature, publicKey)
        return { success: true, data: isValid }
      } catch (error) {
        log.error('IPC verify failed:', error)
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        }
      }
    }
  )

  /**
   * Establish session handler
   */
  ipcMain.handle(
    'signal-protocol:establishSession',
    async (
      _ev,
      accountId: number,
      recipientId: string,
      recipientPublicKey: string,
      preKey: PreKeyBundle
    ) => {
      try {
        const protocol = getSignalProtocol(accountId)
        await protocol.establishSession(recipientId, recipientPublicKey, preKey)
        return { success: true }
      } catch (error) {
        log.error('IPC establishSession failed:', error)
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        }
      }
    }
  )

  /**
   * Has session handler
   */
  ipcMain.handle(
    'signal-protocol:hasSession',
    async (_ev, accountId: number, recipientId: string) => {
      try {
        const protocol = getSignalProtocol(accountId)
        const hasSession = await protocol.hasSession(recipientId)
        return { success: true, data: hasSession }
      } catch (error) {
        log.error('IPC hasSession failed:', error)
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        }
      }
    }
  )

  /**
   * Delete session handler
   */
  ipcMain.handle(
    'signal-protocol:deleteSession',
    async (_ev, accountId: number, recipientId: string) => {
      try {
        const protocol = getSignalProtocol(accountId)
        await protocol.deleteSession(recipientId)
        return { success: true }
      } catch (error) {
        log.error('IPC deleteSession failed:', error)
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        }
      }
    }
  )

  /**
   * Clear state handler
   */
  ipcMain.handle('signal-protocol:clearState', async (_ev, accountId: number) => {
    try {
      const protocol = getSignalProtocol(accountId)
      await protocol.clearState()
      signalProtocolInstances.delete(accountId)
      return { success: true }
    } catch (error) {
      log.error('IPC clearState failed:', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      }
    }
  })

  log.info('Signal Protocol IPC handlers setup complete')
}

/**
 * Clean up Signal Protocol on shutdown
 */
export async function shutdownSignalProtocol(): Promise<void> {
  log.info('Shutting down Signal Protocol instances')
  for (const protocol of signalProtocolInstances.values()) {
    await protocol.clearState()
  }
  signalProtocolInstances.clear()
}
