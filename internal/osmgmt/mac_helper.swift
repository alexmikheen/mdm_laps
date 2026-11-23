// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

import Foundation
import OpenDirectory

signal(SIGPIPE, SIG_IGN)

struct LapsPayload: Codable {
    let action: String
    let targetUser: String
    let targetPass: String
    let oldPass: String?
    let adminUser: String?
    let adminPass: String?
    // Go sets this true only for accounts without a Secure Token.
    let allowAdminReset: Bool?
}

func readStdin() -> LapsPayload? {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    return try? JSONDecoder().decode(LapsPayload.self, from: data)
}

// ResetOutcome distinguishes a real reset from a phantom reset (exit 0 while opendirectoryd refuses).
enum ResetOutcome {
    case ok
    case refused
    case failed
}

// sysadminctl can exit 0 while printing one of these refusal strings.
let resetRefusalMarkers = [
    "Operation is not permitted without secure token unlock",
    "not permitted",
    "Could not set password",
]

func administrativeResetSecure(user: String, newPass: String) -> ResetOutcome {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/sbin/sysadminctl")
    task.arguments = ["-resetPasswordFor", user, "-newPassword", "-"]
    let inPipe = Pipe()
    let outPipe = Pipe()
    task.standardInput = inPipe
    task.standardOutput = outPipe
    task.standardError = outPipe
    do {
        try task.run()
        if let passData = (newPass + "\n").data(using: .utf8) {
            try? inPipe.fileHandleForWriting.write(contentsOf: passData)
        }
        try? inPipe.fileHandleForWriting.close()
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let output = String(data: data, encoding: .utf8) ?? ""
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            fputs("[SWIFT] sysadminctl -resetPasswordFor output: \(trimmed)\n", stderr)
        }
        if resetRefusalMarkers.contains(where: { output.localizedCaseInsensitiveContains($0) }) {
            return .refused
        }
        return task.terminationStatus == 0 ? .ok : .failed
    } catch { return .failed }
}

func localUserRecord(user: String) throws -> ODRecord? {
    let node = try ODNode(session: .default(), type: ODNodeType(kODNodeTypeLocalNodes))
    let query = try ODQuery(
        node: node,
        forRecordTypes: kODRecordTypeUsers,
        attribute: kODAttributeTypeRecordName,
        matchType: ODMatchType(kODMatchEqualTo),
        queryValues: user,
        returnAttributes: kODAttributeTypeNativeOnly,
        maximumResults: 0
    )

    guard let results = try query.resultsAllowingPartial(false) as? [ODRecord] else { return nil }
    return results.first
}

// verifyPasswordNative checks a login password through OpenDirectory.
func verifyPasswordNative(user: String, pass: String) -> Bool {
    do {
        guard let record = try localUserRecord(user: user) else {
            fputs("[SWIFT] User \(user) not found in OpenDirectory\n", stderr)
            return false
        }
        try record.verifyPassword(pass)
        return true
    } catch {
        fputs("[SWIFT] Password verification failed for \(user): \(error)\n", stderr)
        return false
    }
}

// Exit codes for change_password; Go mirrors these raw values in macos.go.
enum ChangeOutcome: Int32 {
    case ok = 0
    case odError = 1
    case authFailed = 2
    case locked = 3
    case resetRefused = 4
    case policyRejected = 5

    var label: String {
        switch self {
        case .ok: return "ok"
        case .odError: return "od-error"
        case .authFailed: return "auth-failed"
        case .locked: return "locked"
        case .resetRefused: return "reset-refused"
        case .policyRejected: return "policy-rejected"
        }
    }
}

let odErrorAccountTemporarilyLocked = 5304
let odErrorAccountLocked = 5305
// OpenDirectory 5402-5407: password policy rejected the new password.
let odErrorPolicyViolations: ClosedRange<Int> = 5402...5407
// OpenDirectory 5200-5205: transient server or transport errors.
let odErrorServerTransport: ClosedRange<Int> = 5200...5205

// changePasswordNative rotates the password and only falls back to sysadminctl when Go sets allowAdminReset.
func changePasswordNative(user: String, oldPass: String?, newPass: String, allowAdminReset: Bool) -> ChangeOutcome {
    var record: ODRecord?
    do {
        record = try localUserRecord(user: user)
    } catch {
        fputs("[SWIFT] OpenDirectory Error: \(error)\n", stderr)
        return .odError
    }
    guard let record else {
        fputs("[SWIFT] User \(user) not found in OpenDirectory\n", stderr)
        return .odError
    }

    if let old = oldPass, !old.isEmpty {
        do {
            try record.changePassword(old, toPassword: newPass)
            fputs("[SWIFT] Password natively changed for \(user) (Secure Token preserved)\n", stdout)
            return .ok
        } catch {
            let code = (error as NSError).code
            let outcome: ChangeOutcome
            switch code {
            case odErrorAccountTemporarilyLocked, odErrorAccountLocked: outcome = .locked
            case odErrorPolicyViolations: outcome = .policyRejected
            case odErrorServerTransport: outcome = .odError
            case 5000, 5101, 5300...5303, 5400, 5401: outcome = .authFailed
            default: outcome = .odError
            }
            fputs("[SWIFT] Authenticated change failed for \(user) (OpenDirectory code \(code), reporting \(outcome.label)): \(error)\n", stderr)
            if outcome == .policyRejected {
                fputs("[SWIFT] The new password itself was rejected by the password policy; no reset can apply it. Reporting \(outcome.label) so the caller retries with a different password.\n", stderr)
                return outcome
            }
            if !allowAdminReset {
                fputs("[SWIFT] Not attempting an administrative reset for \(user): the caller did not permit it (the account holds a Secure Token). Reporting \(outcome.label) so the caller can escalate.\n", stderr)
                return outcome
            }
        }
    }

    guard allowAdminReset else {
        fputs("[SWIFT] No usable current password for \(user) and an administrative reset was not permitted.\n", stderr)
        return .authFailed
    }

    switch administrativeResetSecure(user: user, newPass: newPass) {
    case .ok:
        fputs("[SWIFT] Administrative password reset for \(user) succeeded (sysadminctl printed no refusal).\n", stdout)
        return .ok
    case .refused:
        fputs("[SWIFT] Administrative reset for \(user) was REFUSED by opendirectoryd — reporting failure regardless of the exit code, so no password is escrowed that the device never took.\n", stderr)
        return .resetRefused
    case .failed:
        fputs("[SWIFT] Administrative reset for \(user) failed.\n", stderr)
        return .resetRefused
    }
}

func grantSecureTokenSecure(targetUser: String, targetPass: String, adminUser: String, adminPass: String) -> Bool {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/sbin/sysadminctl")
    task.arguments = ["-adminUser", adminUser, "-adminPassword", "-", "-secureTokenOn", targetUser, "-password", "-"]
    let inPipe = Pipe()
    task.standardInput = inPipe
    do {
        try task.run()
        if let adminData = (adminPass + "\n").data(using: .utf8) {
            try? inPipe.fileHandleForWriting.write(contentsOf: adminData)
        }
        Thread.sleep(forTimeInterval: 0.5)
        if let targetData = (targetPass + "\n").data(using: .utf8) {
            try? inPipe.fileHandleForWriting.write(contentsOf: targetData)
        }
        try? inPipe.fileHandleForWriting.close()
        task.waitUntilExit()
        return task.terminationStatus == 0
    } catch { return false }
}

// sysadminctl can exit 0 even when opendirectoryd refuses the grant, so verify the token state explicitly.
func secureTokenIsEnabled(user: String) -> Bool {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/sbin/sysadminctl")
    task.arguments = ["-secureTokenStatus", user]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = pipe
    do {
        try task.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let output = String(data: data, encoding: .utf8) ?? ""
 // Match the whole phrase. A bare "ENABLED" test is one typo away from a match on "DISABLED".
        return output.contains("is ENABLED") || output.contains("is ON")
    } catch { return false }
}

func grantSecureToken(targetUser: String, targetPass: String, adminUser: String, adminPass: String) -> Bool {
    if grantSecureTokenSecure(targetUser: targetUser, targetPass: targetPass, adminUser: adminUser, adminPass: adminPass) {
        Thread.sleep(forTimeInterval: 1.0) // give opendirectoryd time to commit the SEP credential
        if secureTokenIsEnabled(user: targetUser) {
            fputs("[SWIFT] Token granted securely via stdin.\n", stdout)
            return true
        }
        fputs("[SWIFT] stdin method exited 0 but the token is still not set — not trusting the exit code.\n", stderr)
    }

    fputs("[SWIFT] Secure token grant failed.\n", stderr)
    return false
}

// ==============================================================================
// MAIN EXECUTION
// ==============================================================================

guard let payload = readStdin() else {
    fputs("[SWIFT] Invalid JSON payload received from standard input.\n", stderr)
    exit(1)
}

if payload.action == "change_password" {
    let outcome = changePasswordNative(
        user: payload.targetUser,
        oldPass: payload.oldPass,
        newPass: payload.targetPass,
        allowAdminReset: payload.allowAdminReset ?? false
    )
    exit(outcome.rawValue)
} else if payload.action == "verify_password" {
    exit(verifyPasswordNative(user: payload.targetUser, pass: payload.targetPass) ? 0 : 1)
} else if payload.action == "grant_token" {
    guard let adminUser = payload.adminUser, let adminPass = payload.adminPass else {
        fputs("[SWIFT] Missing admin credentials for token grant.\n", stderr)
        exit(1)
    }
    let success = grantSecureToken(targetUser: payload.targetUser, targetPass: payload.targetPass, adminUser: adminUser, adminPass: adminPass)
    exit(success ? 0 : 1)
} else {
    fputs("[SWIFT] Unknown action requested.\n", stderr)
    exit(1)
}
