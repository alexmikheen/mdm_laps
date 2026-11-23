// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

import AppKit
import Carbon.HIToolbox
import SwiftUI

signal(SIGPIPE, SIG_IGN)

// Native SwiftUI/AppKit auth window run as the console user by golaps (root).
// Protocol: JSON lines on stdin/stdout; typed passwords travel only over the root-owned Unix socket.
// All UI text is compiled in so external callers cannot inject phishing text.

enum Copy {
    static let title = "IT Security Update"
    static let stepAdmin = "Administrator access"
    static let stepPassword = "Mac login password"
    static let stepUpdate = "Security update"
    static let adminActive = "Your action is necessary"
    static let adminBusy = "Waiting for approval"
    static let adminDone = "Granted"
    static let passwordActive = "Your action is necessary"
    static let passwordBusy = "Checking"
    static let passwordDone = "Accepted"
    static let passwordFailed = "Not accepted"
    static let updateBusy = "In progress"
    static let updateDone = "Complete"
    static let updateFailed = "Did not complete"
    static let adminBody = "IT is finishing a security update on this Mac. One step requires temporary administrator access for your account.\n\n1. Click \"Open Admin By Request\".\n2. Select \"Request administrator access\" and confirm with Yes.\n\nThis window continues automatically after macOS grants access."
    static let adminButton = "Open Admin By Request"
    static let adminWaiting = "Approve the request in the Admin By Request window."
    static let body = "IT is updating macOS security settings.\n\nWe are adding a background IT account for FileVault data recovery. To finish this process, macOS requires your local login password.\n\nTo check that this window is real, contact your IT support team."
    static let fieldLabel = "Mac login password"
    static let fieldPlaceholder = "Enter your password"
    static let emptyPassword = "Enter your Mac login password."
    static let helpButton = "Open IT Help Article"
    static let noDeferralsLeft = "You cannot postpone this update again. Complete it now."
    static let screenBlocked = "This update is overdue. Complete it to continue your work."
    static let updateButton = "Update"
    static let working = "The security update is in progress. This takes a few seconds."
    static let doneTitle = "Thank you"
    static let doneBody = "The IT security update is complete. This window closes in a moment."
    static let errorTitle = "The update did not complete"
    static let errorBody = "The security update could not finish on this Mac. You do not need to take action now. Your IT team has the details and will try again.\n\nFor questions, contact your IT support team."
    static func paused(minutes: Int) -> String {
        "macOS did not accept the password. You can try again in \(minutes) \(minutes == 1 ? "minute" : "minutes")."
    }
    static let pauseEnding = "Waiting for the next attempt."
    static let failedTitle = "Password not accepted"
    static let failedBody = "Each password attempt failed, so the update cannot continue today.\n\nFor help, contact your IT support team."
    static let teamButton = "Contact IT Support"
    static let okButton = "OK"
    static let teamChannel = ""
    static let resultSeconds: TimeInterval = 15
    static let helpArticle = ""
    static let backdropFile = "/usr/local/golaps/backdrop.jpg"

    static func keyboardLayout(_ name: String) -> String {
        "Keyboard layout: \(name). Switch to ABC if your password has Latin letters."
    }

    static func laterButton(left: Int) -> String {
        "Later (\(left) left)"
    }

    static func wrongPassword(attempt: Int, of maxAttempts: Int) -> String {
        "Incorrect password. Please try again. (Attempt \(attempt) of \(maxAttempts))"
    }
}

enum Brand {
    static func rgb(_ hex: UInt32) -> Color {
        Color(red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255, blue: Double(hex & 0xFF) / 255)
    }

    static let blue = rgb(0x2962FF)
    static let background = rgb(0x131722)
    static let surface = rgb(0x1E222D)
    static let border = rgb(0x2A2E39)
    static let text = rgb(0xD1D4DC)
    static let secondaryText = rgb(0x787B86)
    static let red = rgb(0xF23645)
    static let orange = rgb(0xFF9800)
    static let green = rgb(0x089981)
    static let markTile = rgb(0x0F0F0F)
}

struct WindowRequest: Decodable {
    let attempt: Int
    let maxAttempts: Int
    let deferralsLeft: Int
    let blockScreen: Bool?
    let needAdmin: Bool?
    let timeoutSeconds: Int
}

struct WindowCommand: Decodable {
    let cmd: String
    let attempt: Int?
    let view: String?
    let seconds: Int?
}

func send(_ fields: [String: String]) {
    guard var line = try? JSONEncoder().encode(fields) else { return }
    line.append(0x0A)
    try? FileHandle.standardOutput.write(contentsOf: line)
}

// Restore the previous keyboard layout on the main thread before exiting.
func quit(_ status: Int32) -> Never {
    if Thread.isMainThread {
        KeyboardLayout.restore()
    } else {
        DispatchQueue.main.sync { KeyboardLayout.restore() }
    }
    exit(status)
}

func finish(event: String) -> Never {
    send(["event": event])
    quit(0)
}

// PasswordChannel verifies peer UID via getpeereid before sending passwords over the Unix socket.
enum PasswordChannel {
#if LAPS_TEST
    static let path = String(cString: getenv("LAPS_TEST_AUTH_SOCKET"))
    static let ownerUID = getuid()
#else
    static let path = "/var/run/golaps_auth.sock"
    static let ownerUID: uid_t = 0
#endif

    private static func connect() -> Int32? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var noSigPipe: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            close(fd)
            return nil
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let length = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, length) }
        }
        var peer: uid_t = 0
        var group: gid_t = 0
        guard connected == 0, getpeereid(fd, &peer, &group) == 0, peer == ownerUID else {
            close(fd)
            return nil
        }
        return fd
    }

    static func reachable() -> Bool {
        guard let fd = connect() else { return false }
        close(fd)
        return true
    }

    static func deliver(_ password: String) -> Bool {
        guard let fd = connect() else { return false }
        defer { close(fd) }
        let line = Array((password + "\n").utf8)
        var sent = 0
        while sent < line.count {
            let count = line[sent...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            guard count > 0 else { return false }
            sent += count
        }
        return true
    }
}

// Switch to an ASCII layout while the prompt is open and restore the previous layout on exit.
enum KeyboardLayout {
    private static var earlier: TISInputSource?

    private static func isASCII(_ source: TISInputSource) -> Bool {
        guard let raw = TISGetInputSourceProperty(source, kTISPropertyInputSourceIsASCIICapable) else { return false }
        return CFBooleanGetValue(Unmanaged<CFBoolean>.fromOpaque(raw).takeUnretainedValue())
    }

 // nonASCIIName returns the name of the current layout when that layout cannot type ASCII, and nil for an ASCII layout.
    static func nonASCIIName() -> String? {
        guard let current = TISCopyCurrentKeyboardInputSource()?.takeRetainedValue(), !isASCII(current) else { return nil }
        guard let raw = TISGetInputSourceProperty(current, kTISPropertyLocalizedName) else { return "" }
        return Unmanaged<CFString>.fromOpaque(raw).takeUnretainedValue() as String
    }

    static func selectASCII() {
        guard let current = TISCopyCurrentKeyboardInputSource()?.takeRetainedValue(), !isASCII(current) else { return }
        guard let ascii = TISCopyCurrentASCIICapableKeyboardLayoutInputSource()?.takeRetainedValue() else { return }
        if TISSelectInputSource(ascii) == noErr {
            earlier = current
        }
    }

    static func restore() {
        if let source = earlier {
            TISSelectInputSource(source)
            earlier = nil
        }
    }
}

enum Step {
    case admin
    case password
    case working
    case done
    case error
    case failed

    var isResult: Bool { self == .done || self == .error || self == .failed }
}

final class WindowState: ObservableObject {
    @Published var step: Step
    @Published var password = ""
    @Published var attempt: Int
    @Published var message: String?
    @Published var isWaiting = false
    @Published var adminRequested = false
    @Published var layoutName: String?
    @Published var pauseLeft = 0
    // isPaused stays true until the parent sends view "password" so early submissions are not dropped.
    @Published var isPaused = false
    @Published var pauseEnding = false

    @Published var hasAdminStep: Bool
    @Published var passwordAccepted = false

    let maxAttempts: Int
    let deferralsLeft: Int
    let blockScreen: Bool
    var onHelp: (() -> Void)?
    var onResult: (() -> Void)?
    private let timeout: TimeInterval
    private var idleTimer: Timer?
    private var pauseTimer: Timer?
    // Track pause end by wall clock (plus wake notifications) because Timer freezes during macOS sleep.
    private var pauseUntil: Date?
    private var wakeObserver: NSObjectProtocol?

    init(request: WindowRequest) {
        maxAttempts = min(max(request.maxAttempts, 1), 10)
        attempt = min(max(request.attempt, 1), maxAttempts)
        deferralsLeft = max(request.deferralsLeft, 0)
        blockScreen = request.blockScreen ?? false
        hasAdminStep = request.needAdmin ?? false
        step = (request.needAdmin ?? false) ? .admin : .password
        timeout = TimeInterval(min(max(request.timeoutSeconds, 1), 3600))
        if attempt > 1 {
            message = Copy.wrongPassword(attempt: attempt, of: maxAttempts)
        }
        restartIdleTimer()
    }

    // Add timer to .common run loop modes so it still fires while the user drags the window.
    private func restartIdleTimer() {
        idleTimer?.invalidate()
        let timer = Timer(timeInterval: timeout, repeats: false) { _ in
            finish(event: "timeout")
        }
        RunLoop.main.add(timer, forMode: .common)
        idleTimer = timer
    }

    func requestAdmin() {
        adminRequested = true
        send(["event": "abr"])
        restartIdleTimer()
    }

    func show(view: String, seconds: Int = 0) {
        switch view {
        case "admin":
            clearPause()
            hasAdminStep = true
            step = .admin
            adminRequested = false
            isWaiting = false
            restartIdleTimer()
        case "password":
            isWaiting = false
            if isPaused {
                endPause()
                return
            }
            guard step == .admin else { return }
            step = .password
            adminRequested = false
            restartIdleTimer()
        case "paused":
            pause(seconds: seconds)
        case "working":
            passwordAccepted = true
            step = .working
            isWaiting = false
            message = nil
            restartIdleTimer()
        case "done":
            showResult(.done)
        case "error":
            showResult(.error)
        case "failed":
            showResult(.failed)
        default:
            break
        }
    }

    private func pause(seconds: Int) {
        guard step == .password else { return }
        pauseUntil = Date().addingTimeInterval(TimeInterval(min(max(seconds, 1), 3600)))
        isPaused = true
        pauseEnding = false
        attempt = 1
        password = ""
        isWaiting = false
        message = nil
        idleTimer?.invalidate()
        pauseTimer?.invalidate()
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            self?.updatePause()
        }
        RunLoop.main.add(timer, forMode: .common)
        pauseTimer = timer
        if wakeObserver == nil {
            wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
                self?.updatePause()
            }
        }
        updatePause()
    }

    private func updatePause() {
        guard let until = pauseUntil else { return }
        let left = Int(until.timeIntervalSinceNow.rounded(.up))
        if left <= 0 {
            pauseLeft = 0
            pauseEnding = true
        } else {
            pauseLeft = left
        }
    }

    private func endPause() {
        clearPause()
        restartIdleTimer()
    }

    private func clearPause() {
        pauseTimer?.invalidate()
        pauseTimer = nil
        if let observer = wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
            wakeObserver = nil
        }
        pauseUntil = nil
        pauseLeft = 0
        isPaused = false
        pauseEnding = false
    }

    private func showResult(_ result: Step) {
        step = result
        isWaiting = false
        idleTimer?.invalidate()
        let timer = Timer(timeInterval: Copy.resultSeconds, repeats: false) { _ in
            quit(0)
        }
        RunLoop.main.add(timer, forMode: .common)
        idleTimer = timer
        onResult?()
    }

    func close() {
        quit(0)
    }

    func openTeamChannel() {
        if let url = URL(string: Copy.teamChannel) {
            NSWorkspace.shared.open(url)
        }
    }

    func submit() {
        guard step == .password, !isWaiting, !isPaused else { return }
        guard !password.isEmpty else {
            message = Copy.emptyPassword
            return
        }
        isWaiting = true
        message = nil
 // Without the socket of root the window has no safe way to give the password. It ends. The parent then logs a failed window, and the prompt returns on the next check-in.
        guard PasswordChannel.deliver(password) else { quit(4) }
        password = ""
        restartIdleTimer()
    }

 // The parent checked the password and it was wrong. The parent owns the attempt number.
    func showWrongPassword(attempt next: Int) {
        attempt = min(max(next, 1), maxAttempts)
        message = Copy.wrongPassword(attempt: attempt, of: maxAttempts)
        isWaiting = false
        restartIdleTimer()
    }

    func later() {
        finish(event: "later")
    }

 // The window runs as the console user in the session of that user. The link therefore opens in the user's default browser.
    func openHelp() {
        if let url = URL(string: Copy.helpArticle) {
            NSWorkspace.shared.open(url)
        }
        onHelp?()
    }
}

// ==============================================================================
// 5. VIEW
// ==============================================================================

// The two button looks of the window, in the brand colours. The system styles take the accent colour of the user, which is not always blue.
struct PrimaryButton: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundColor(.white)
 // A button label stays on one line. A label that wraps makes the button two lines high.
            .lineLimit(1)
            .fixedSize()
            .padding(.horizontal, 16)
            .padding(.vertical, 7)
            .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(Brand.blue.opacity(configuration.isPressed ? 0.75 : 1)))
            .opacity(isEnabled ? 1 : 0.5)
    }
}

struct SecondaryButton: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .foregroundColor(Brand.text)
            .lineLimit(1)
            .fixedSize()
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(Brand.border.opacity(configuration.isPressed ? 0.6 : 1)))
            .opacity(isEnabled ? 1 : 0.5)
    }
}

// BackdropView draws the backdrop picture so that it fills the view. The picture keeps its proportions, and the part that does not fit is cut off equally on both sides. The view draws the picture itself and does not use a layer. The same code then draws on the screen and in an offscreen check.
final class BackdropView: NSView {
    var picture: NSImage?

    override var isOpaque: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        NSColor(calibratedWhite: 0.05, alpha: 1).setFill()
        bounds.fill()
        guard let picture, picture.size.width > 0, picture.size.height > 0 else { return }
        let scale = max(bounds.width / picture.size.width, bounds.height / picture.size.height)
        let size = NSSize(width: picture.size.width * scale, height: picture.size.height * scale)
        let origin = NSPoint(x: bounds.midX - size.width / 2, y: bounds.midY - size.height / 2)
        picture.draw(in: NSRect(origin: origin, size: size), from: .zero, operation: .copy, fraction: 1)
    }
}

// Backdrop covers each screen behind the window. It is the last step of the escalation, and the parent turns it on. It is a strong reminder and not a lock: the window still closes after the timeout, and the system shortcuts still work.
final class Backdrop {
    private var windows: [NSWindow] = []
    private var resumeTimer: Timer?

    func show() {
 // Without the picture file the backdrop is plain dark. The block must not depend on a picture.
        let picture = NSImage(contentsOfFile: Copy.backdropFile)
        for screen in NSScreen.screens {
            let cover = NSWindow(contentRect: screen.frame, styleMask: [.borderless], backing: .buffered, defer: false)
 // One level below the window, above the windows of all other apps.
            cover.level = NSWindow.Level(rawValue: NSWindow.Level.floating.rawValue - 1)
            cover.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
            cover.isOpaque = true
            cover.backgroundColor = .black
            let view = BackdropView(frame: NSRect(origin: .zero, size: screen.frame.size))
            view.picture = picture
            cover.contentView = view
            cover.setFrame(screen.frame, display: true)
            cover.orderFront(nil)
            windows.append(cover)
        }
    }

 // The help article opens in a browser, and the backdrop would hide it. The backdrop therefore moves away for a short time and then comes back.
 // hide takes the backdrop away for good. The task ended, so there is nothing left to remind the user of.
    func hide() {
        resumeTimer?.invalidate()
        windows.forEach { $0.orderOut(nil) }
    }

    func pause(for seconds: TimeInterval, then restore: @escaping () -> Void) {
        windows.forEach { $0.orderOut(nil) }
        resumeTimer?.invalidate()
        resumeTimer = Timer.scheduledTimer(withTimeInterval: seconds, repeats: false) { [weak self] _ in
            self?.windows.forEach { $0.orderFront(nil) }
            restore()
        }
    }
}

// Borderless windows do not accept keyboard focus by default.
final class PromptWindow: NSWindow {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}

enum RowState {
    case pending
    case active
    case busy
    case done
    case failed
}

struct PipelineRow: View {
    let title: String
    let status: String
    let state: RowState

    var body: some View {
        HStack(spacing: 10) {
            mark
                .frame(width: 18, height: 18)
            Text(title)
                .font(.system(size: 13, weight: state == .pending ? .regular : .semibold))
                .foregroundColor(state == .pending ? Brand.secondaryText : .white)
            Spacer()
            Text(status)
                .font(.system(size: 12))
                .foregroundColor(statusColour)
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private var mark: some View {
        switch state {
        case .pending:
            Circle().stroke(Brand.border, lineWidth: 1.5).padding(1)
        case .active:
            ZStack {
                Circle().stroke(Brand.blue, lineWidth: 2).padding(1)
                Circle().fill(Brand.blue).padding(5)
            }
        case .busy:
            ProgressView().controlSize(.small).accessibilityLabel(status)
        case .done:
            Image(systemName: "checkmark.circle.fill").font(.system(size: 17)).foregroundColor(Brand.green)
        case .failed:
            Image(systemName: "xmark.circle.fill").font(.system(size: 17)).foregroundColor(Brand.red)
        }
    }

    private var statusColour: Color {
        switch state {
        case .done:
            return Brand.green
        case .failed:
            return Brand.red
        case .active:
            return Brand.blue
        case .pending, .busy:
            return Brand.secondaryText
        }
    }
}

struct AuthView: View {
    @ObservedObject var state: WindowState
    @FocusState private var passwordFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header
            pipeline
            Rectangle().fill(Brand.border).frame(height: 1)

            switch state.step {
            case .admin:
                adminStep
            case .password:
                passwordStep
            case .working:
                plainText(Copy.working)
            case .done:
                resultText(title: Copy.doneTitle, text: Copy.doneBody)
            case .error:
                resultText(title: Copy.errorTitle, text: Copy.errorBody)
            case .failed:
                resultText(title: Copy.failedTitle, text: Copy.failedBody)
            }

            if (state.step == .admin || state.step == .password) && (state.blockScreen || state.deferralsLeft == 0) {
                Text(state.blockScreen ? Copy.screenBlocked : Copy.noDeferralsLeft)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(Brand.secondaryText)
            }

            buttons
        }
        .padding(24)
        .frame(width: 520)
        .foregroundColor(Brand.text)
 // The brand colour is not fully opaque, so the backdrop picture shows through the blur a little.
        .background(Brand.background.opacity(0.94))
        .background(.ultraThinMaterial)
 // The window has no frame of the system, so the view makes the round corners itself.
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .onAppear { focusPassword() }
        .onChange(of: state.isWaiting) { waiting in
            if !waiting { focusPassword() }
        }
        .onChange(of: state.pauseLeft) { left in
            if left == 0 { focusPassword() }
        }
        .onChange(of: state.step) { _ in focusPassword() }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            ZStack {
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(Brand.markTile)
                    .frame(width: 56, height: 56)
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 26, weight: .semibold))
                    .foregroundColor(.white)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(Copy.title)
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundColor(.white)
                Text("Account: \(NSUserName())")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(Brand.secondaryText)
            }
            Spacer()
        }
    }

 // The list of the steps. It stays in the window from the first view to the last, so the user always sees the full task and the place in it.
    private var pipeline: some View {
        VStack(alignment: .leading, spacing: 10) {
            if state.hasAdminStep {
                PipelineRow(title: Copy.stepAdmin, status: adminStatus, state: adminState)
            }
            PipelineRow(title: Copy.stepPassword, status: passwordStatus, state: passwordState)
            PipelineRow(title: Copy.stepUpdate, status: updateStatus, state: updateState)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Brand.surface))
    }

    private var adminState: RowState {
        guard state.step == .admin else { return .done }
        return state.adminRequested ? .busy : .active
    }

    private var adminStatus: String {
        switch adminState {
        case .done:
            return Copy.adminDone
        case .busy:
            return Copy.adminBusy
        default:
            return Copy.adminActive
        }
    }

    private var passwordState: RowState {
        switch state.step {
        case .admin:
            return state.passwordAccepted ? .done : .pending
        case .password:
            return state.isWaiting ? .busy : .active
        case .working, .done, .error:
            return .done
        case .failed:
            return .failed
        }
    }

    private var passwordStatus: String {
        switch passwordState {
        case .pending:
            return ""
        case .active:
            return Copy.passwordActive
        case .busy:
            return Copy.passwordBusy
        case .done:
            return Copy.passwordDone
        case .failed:
            return Copy.passwordFailed
        }
    }

    private var updateState: RowState {
        switch state.step {
        case .working:
            return .busy
        case .done:
            return .done
        case .error:
            return .failed
        case .admin, .password, .failed:
            return .pending
        }
    }

    private var updateStatus: String {
        switch updateState {
        case .busy:
            return Copy.updateBusy
        case .done:
            return Copy.updateDone
        case .failed:
            return Copy.updateFailed
        default:
            return ""
        }
    }

    private var adminStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            plainText(Copy.adminBody)
            if state.adminRequested {
                Text(Copy.adminWaiting)
                    .font(.system(size: 12))
                    .foregroundColor(Brand.secondaryText)
            }
        }
    }

    private var passwordStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            plainText(Copy.body)

            VStack(alignment: .leading, spacing: 8) {
                Text(Copy.fieldLabel)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(Brand.secondaryText)

                SecureField(Copy.fieldPlaceholder, text: $state.password)
                    .textFieldStyle(.plain)
                    .font(.system(size: 13))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(Brand.surface))
                    .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).stroke(passwordFocused ? Brand.blue : Brand.border, lineWidth: passwordFocused ? 2 : 1))
                    .focused($passwordFocused)
                    .onSubmit { state.submit() }
                    .disabled(state.isWaiting || state.isPaused)
                    .accessibilityLabel(Copy.fieldLabel)

                if let layout = state.layoutName {
                    notice(Copy.keyboardLayout(layout), icon: "keyboard", colour: Brand.orange)
                }
                if state.isPaused {
 // The countdown shows whole minutes and rounds up, so it never shows zero while it runs. At zero the window waits for the parent.
                    notice(state.pauseEnding ? Copy.pauseEnding : Copy.paused(minutes: (state.pauseLeft + 59) / 60), icon: "clock.fill", colour: Brand.red)
                } else if let message = state.message {
                    notice(message, icon: "exclamationmark.triangle.fill", colour: Brand.red)
                }
            }
        }
    }

    private func plainText(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 13))
            .fixedSize(horizontal: false, vertical: true)
    }

    private func resultText(title: String, text: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 15, weight: .semibold))
                .foregroundColor(.white)
            plainText(text)
        }
    }

    private func notice(_ text: String, icon: String, colour: Color) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 11))
            Text(text)
                .font(.system(size: 12))
        }
        .foregroundColor(colour)
    }

    private var buttons: some View {
        HStack(spacing: 10) {
            switch state.step {
            case .admin, .password:
                if !Copy.helpArticle.isEmpty {
                    linkButton(Copy.helpButton) { state.openHelp() }
                }
            case .error, .failed:
                if !Copy.teamChannel.isEmpty {
                    linkButton(Copy.teamButton) { state.openTeamChannel() }
                }
            case .working, .done:
                EmptyView()
            }

            Spacer()

            if (state.step == .admin || state.step == .password) && state.deferralsLeft > 0 {
 // No Escape shortcut on purpose. A reflex key press must not use one of the postponements.
                Button(Copy.laterButton(left: state.deferralsLeft)) { state.later() }
                    .buttonStyle(SecondaryButton())
                    .disabled(state.isWaiting)
            }

            switch state.step {
            case .admin:
                Button(Copy.adminButton) { state.requestAdmin() }
                    .buttonStyle(PrimaryButton())
                    .keyboardShortcut(.defaultAction)
            case .password:
                Button(Copy.updateButton) { state.submit() }
                    .buttonStyle(PrimaryButton())
                    .keyboardShortcut(.defaultAction)
                    .disabled(state.isWaiting || state.isPaused)
            case .working:
                EmptyView()
            case .done, .error, .failed:
                Button(Copy.okButton) { state.close() }
                    .buttonStyle(PrimaryButton())
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(.top, 4)
    }

    private func linkButton(_ title: String, action: @escaping () -> Void) -> some View {
        Button(title, action: action)
            .buttonStyle(.plain)
            .font(.system(size: 13))
            .foregroundColor(Brand.blue)
    }

    private func focusPassword() {
        guard state.step == .password else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            passwordFocused = true
        }
    }
}

guard let firstLine = readLine(strippingNewline: true),
      let request = try? JSONDecoder().decode(WindowRequest.self, from: Data(firstLine.utf8))
else {
    fputs("golaps_auth: the first line of stdin is not a window request. golaps starts this program.\n", stderr)
    exit(2)
}

// Refuse to open without a root-owned socket so another user process cannot abuse this window.
guard PasswordChannel.reachable() else {
    fputs("golaps_auth: the password socket of golaps is not there. golaps starts this program.\n", stderr)
    exit(3)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
app.appearance = NSAppearance(named: .darkAqua)

// Register a hidden Edit menu so Cmd+C/V/X/A work in SecureField.
let editMenu = NSMenu(title: "Edit")
editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
let editItem = NSMenuItem()
editItem.submenu = editMenu
let mainMenu = NSMenu()
mainMenu.addItem(editItem)
app.mainMenu = mainMenu

let state = WindowState(request: request)
let hosting = NSHostingView(rootView: AuthView(state: state))

// The window has no title bar and no close button. The only ways out are the buttons, the timeout and the parent.
let window = PromptWindow(
    contentRect: NSRect(x: 0, y: 0, width: 520, height: hosting.fittingSize.height),
    styleMask: [.borderless],
    backing: .buffered,
    defer: false
)
// The title is not shown, but VoiceOver reads it.
window.title = Copy.title
window.isMovableByWindowBackground = true
window.isOpaque = false
window.backgroundColor = .clear
window.hasShadow = true
window.level = .floating
window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
window.contentView = hosting
window.center()

// The backdrop goes up first, so the window is in front of it.
let backdrop = Backdrop()
if state.blockScreen {
    backdrop.show()
    state.onHelp = {
        backdrop.pause(for: 120) {
            window.makeKeyAndOrderFront(nil)
            app.activate(ignoringOtherApps: true)
        }
    }
    state.onResult = { backdrop.hide() }
}

window.makeKeyAndOrderFront(nil)
app.activate(ignoringOtherApps: true)

// Tell the parent that the user can see the window. The parent starts the deferral budget only after this line. Without it, the parent logs a failed window and ends the prompt.
send(["event": "shown"])

// The window is in front and has the keyboard now. Select the ASCII layout, then follow each later change of the layout.
KeyboardLayout.selectASCII()
state.layoutName = KeyboardLayout.nonASCIIName()
DistributedNotificationCenter.default().addObserver(
    forName: NSNotification.Name(kTISNotifySelectedKeyboardInputSourceChanged as String), object: nil, queue: .main
) { _ in
    state.layoutName = KeyboardLayout.nonASCIIName()
}

// The commands of the parent arrive on a background thread. The end of stdin is the close signal. It also arrives when the parent dies, so the window cannot stay behind as an orphan that asks for a password.
Thread.detachNewThread {
    while let line = readLine(strippingNewline: true) {
        guard let command = try? JSONDecoder().decode(WindowCommand.self, from: Data(line.utf8)) else { continue }
        DispatchQueue.main.async {
            if command.cmd == "show", let view = command.view {
                state.show(view: view, seconds: command.seconds ?? 0)
            } else if command.cmd == "wrong", let attempt = command.attempt {
                state.showWrongPassword(attempt: attempt)
            }
        }
    }
    quit(0)
}

app.run()
