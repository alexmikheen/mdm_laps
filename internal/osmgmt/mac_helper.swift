import Foundation
import OpenDirectory

struct LapsPayload: Codable {
    let action: String
    let targetUser: String
    let targetPass: String
    let oldPass: String?
    let adminUser: String?
    let adminPass: String?
    // Set by Go only for token-less accounts. Absent means false — a payload from an older binary must not be able to trigger a reset that could break a FileVault chain.
    let allowAdminReset: Bool?
}

func readStdin() -> LapsPayload? {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    return try? JSONDecoder().decode(LapsPayload.self, from: data)
}

// ============================================================================== 1. ADMINISTRATIVE RESET ==============================================================================

// ResetOutcome separates "sysadminctl performed the reset" from "sysadminctl exited 0 while opendirectoryd refused it" — the phantom that escrowed passwords the machine never received (observed in production).
enum ResetOutcome {
    case ok
    case refused
    case failed
}

// Markers sysadminctl prints while still exiting 0. Detection is by OUTPUT on purpose: verifying by re-authenticating is what v1.1.15 did, and every failed attempt spent an authentication against the account. None of these strings appear in a successful reset — the "will not allow user to use FDE" notice sysadminctl always prints does not match any of them.
let resetRefusalMarkers = [
    "Operation is not permitted without secure token unlock",
    "not permitted",
    "Could not set password",
]

// stdin only, no argv fallback: production logs showed the direct-arguments fallback firing repeatedly without a single success, so it only ever put the password into an argument list.
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
            inPipe.fileHandleForWriting.write(passData)
        }
        inPipe.fileHandleForWriting.closeFile()
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let output = String(data: data, encoding: .utf8) ?? ""
        // Capturing the pipe means this output no longer reaches the Go log on its own, and it is the only evidence of a refusal — so re-emit it. The Go side scrubs it through redactSecrets before logging.
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

// ============================================================================== 2. NATIVE OPENDIRECTORY ROTATION ==============================================================================

// localUserRecord looks up a local account in OpenDirectory.
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

// ChangeOutcome is this helper's exit code for `change_password`. The helper reports WHAT happened; the Go side owns the policy decision, because only it knows whether the account holds a Secure Token and whether recreation is acceptable.
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

let odErrorAccountLocked = 5305
// 5402...5407 all mean the NEW password (or its timing) failed the device's password policy: 5402 quality, 5403 too short, 5404 too long, 5405 needs letter, 5406 needs digit, 5407 change too soon. The account is healthy — reporting any of these as auth-failed made Go recreate a working admin over a rejected new password (observed in production).
let odErrorPolicyViolations: ClosedRange<Int> = 5402...5407

// changePasswordNative rotates the password and reports the outcome. It NEVER decides on its own to fall back to an administrative reset: for an account that holds a Secure Token that reset either reports a phantom success or silently breaks the SEP/FileVault chain, and this process cannot know the token state or what the caller wants done about it. allowAdminReset therefore comes from Go, which sets it only for token-less accounts (nothing left to break). It defaults to false at the call site: fail-safe, so a payload from an older binary cannot trigger a risky reset.
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
            case odErrorAccountLocked: outcome = .locked
            case odErrorPolicyViolations: outcome = .policyRejected
            default: outcome = .authFailed
            }
            fputs("[SWIFT] Authenticated change failed for \(user) (OpenDirectory code \(code), reporting \(outcome.label)): \(error)\n", stderr)
            if outcome == .policyRejected {
                // An administrative reset submits the SAME rejected password to the SAME policy — it cannot help, and against a token holder it is the phantom-reset risk. Bail out for both callers.
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

// ============================================================================== 3. SECURE TOKEN GRANT ==============================================================================

// stdin only, no argv fallback — same fleet evidence as the administrative reset above.
func grantSecureTokenSecure(targetUser: String, targetPass: String, adminUser: String, adminPass: String) -> Bool {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/sbin/sysadminctl")
    task.arguments = ["-adminUser", adminUser, "-adminPassword", "-", "-secureTokenOn", targetUser, "-password", "-"]
    let inPipe = Pipe()
    task.standardInput = inPipe
    do {
        try task.run()
        if let adminData = (adminPass + "\n").data(using: .utf8) {
            inPipe.fileHandleForWriting.write(adminData)
        }
        Thread.sleep(forTimeInterval: 0.5)
        if let targetData = (targetPass + "\n").data(using: .utf8) {
            inPipe.fileHandleForWriting.write(targetData)
        }
        inPipe.fileHandleForWriting.closeFile()
        task.waitUntilExit()
        return task.terminationStatus == 0
    } catch { return false }
}

// secureTokenIsEnabled asks macOS for the real token state. This exists because `sysadminctl` exits 0 even when opendirectoryd refused the operation outright — observed in the unified log as "Failed to enable SEP credential: Credential is not an admin" / ODErrorCredentialsNotAuthorized (error 5101) beside a process that still returned status 0. Trusting the exit code therefore reported a phantom success.
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
        // Match the whole phrase — a bare "ENABLED" test is one typo from matching "DISABLED".
        return output.contains("is ENABLED") || output.contains("is ON")
    } catch { return false }
}

func grantSecureToken(targetUser: String, targetPass: String, adminUser: String, adminPass: String) -> Bool {
    if grantSecureTokenSecure(targetUser: targetUser, targetPass: targetPass, adminUser: adminUser, adminPass: adminPass) {
        Thread.sleep(forTimeInterval: 1.0) // let opendirectoryd commit the SEP credential
        if secureTokenIsEnabled(user: targetUser) {
            fputs("[SWIFT] Token granted securely via stdin.\n", stdout)
            return true
        }
        fputs("[SWIFT] stdin method exited 0 but the token is still not set — not trusting the exit code.\n", stderr)
    }

    fputs("[SWIFT] Secure token grant failed.\n", stderr)
    return false
}

// ============================================================================== MAIN EXECUTION ==============================================================================

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
