// Unambiguous characters only, so a generated password can be read aloud or retyped.
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'

export function generatePassword(length = 20) {
  const values = new Uint32Array(length)
  crypto.getRandomValues(values)
  return Array.from(values, value => ALPHABET[value % ALPHABET.length]).join('')
}
