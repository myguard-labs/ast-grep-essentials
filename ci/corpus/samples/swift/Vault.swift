import CryptoKit
import Foundation
import LocalAuthentication

enum VaultError: Error {
    case authenticationFailed
    case sealFailed
}

/// Seals small secrets with a key held in the keychain.
final class Vault {
    private let key: SymmetricKey

    init(key: SymmetricKey) {
        self.key = key
    }

    func seal(_ plaintext: Data) throws -> Data {
        guard let combined = try AES.GCM.seal(plaintext, using: key).combined else {
            throw VaultError.sealFailed
        }
        return combined
    }

    func open(_ sealed: Data) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key)
    }

    func unlock(reason: String, completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            completion(false)
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
            completion(success)
        }
    }

    static func derive(from password: String, salt: Data) -> SymmetricKey {
        let input = SymmetricKey(data: Data(password.utf8))
        return HKDF<SHA256>.deriveKey(inputKeyMaterial: input, salt: salt, outputByteCount: 32)
    }
}
