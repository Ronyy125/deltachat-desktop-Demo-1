import crypto from 'crypto'

/**
 * AES-256 Encryption Service
 * Encrypts and decrypts messages using AES-256-GCM algorithm
 */

/**
 * Encrypts a message using AES-256
 * @param message - The plain text message to encrypt
 * @param password - The password to derive the encryption key from
 * @returns Encrypted message in format: salt:iv:authTag:encryptedData
 */
export function encryptMessage(message: string, password: string): string {
  try {
    // Generate random salt for key derivation
    const salt = crypto.randomBytes(16)

    // Derive encryption key from password using PBKDF2
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')

    // Generate random initialization vector for AES
    const iv = crypto.randomBytes(16)

    // Create AES-256-GCM cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)

    // Encrypt the message
    let encrypted = cipher.update(message, 'utf8', 'hex')
    encrypted += cipher.final('hex')

    // Get authentication tag for integrity checking
    const authTag = cipher.getAuthTag()

    // Combine all components: salt:iv:authTag:encryptedData
    return (
      salt.toString('hex') +
      ':' +
      iv.toString('hex') +
      ':' +
      authTag.toString('hex') +
      ':' +
      encrypted
    )
  } catch (error) {
    console.error('Encryption failed:', error)
    throw new Error('Failed to encrypt message')
  }
}

/**
 * Decrypts a message that was encrypted with encryptMessage()
 * @param encrypted - The encrypted message in format: salt:iv:authTag:encryptedData
 * @param password - The password used to encrypt the message
 * @returns Decrypted plain text message
 */
export function decryptMessage(encrypted: string, password: string): string {
  try {
    // Split the combined string into its components
    const parts = encrypted.split(':')

    if (parts.length !== 4) {
      throw new Error('Invalid encrypted message format')
    }

    const salt = Buffer.from(parts[0], 'hex')
    const iv = Buffer.from(parts[1], 'hex')
    const authTag = Buffer.from(parts[2], 'hex')
    const encryptedData = parts[3]

    // Derive the same key using the same password and salt
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')

    // Create AES-256-GCM decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)

    // Set the authentication tag for integrity verification
    decipher.setAuthTag(authTag)

    // Decrypt the message
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8')
    decrypted += decipher.final('utf8')

    return decrypted
  } catch (error) {
    console.error('Decryption failed:', error)
    throw new Error('Failed to decrypt message')
  }
}

/**
 * Checks if a string appears to be encrypted (has the expected format)
 * @param str - String to check
 * @returns true if string matches encrypted format
 */
export function isEncrypted(str: string): boolean {
  if (typeof str !== 'string') return false
  const parts = str.split(':')
  return (
    parts.length === 4 &&
    parts[0].length === 32 && // 16 bytes = 32 hex chars for salt
    parts[1].length === 32 && // 16 bytes = 32 hex chars for iv
    parts[2].length === 32 && // 16 bytes = 32 hex chars for authTag
    parts[3].length > 0 // encryptedData
  )
}
