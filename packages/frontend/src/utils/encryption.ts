- Import crypto module at the top
- Create 2 functions: encrypt() and decrypt()
- Export them so other files can use them

import crypto from 'crypto'

export function encryptMessage(message: string, password: string): string {
  // Logic here
  return encryptedMessage
}

export function decryptMessage(encrypted: string, password: string): string {
  // Logic here
  return originalMessage
}
