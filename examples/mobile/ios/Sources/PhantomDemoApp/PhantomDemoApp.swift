// SPDX-License-Identifier: Apache-2.0
//
// PhantomDemoApp — the SwiftUI entry point for the Phantom Protocol iOS sample.
// A minimal chat client that exercises the post-quantum transport: pinned
// connect (with 0-RTT resume when a fresh ticket is cached), encrypted send/recv,
// connection-state surfacing, and reconnect-with-0-RTT on a network change.
//
// Note: the "Call migrate() API" button exercises PhantomSession.migrate(...)
// for API-completeness only — it is a no-op over the TCP transport exposed by
// connectPinned. The working recovery pattern is the "Reconnect (0-RTT)" button
// (and the automatic NetworkPathMonitor handler).
//
// All networking lives in PhantomDemoKit's PhantomChatViewModel; this file is
// just the view layer.

import SwiftUI
import PhantomProtocol
import PhantomDemoKit

@main
struct PhantomDemoApp: App {
    @StateObject private var viewModel = PhantomDemoApp.makeViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView(viewModel: viewModel)
        }
    }

    /// Builds the ViewModel with the pinned server config. The pinned key is
    /// loaded from the bundled resource (Security Invariant 1) — never fetched at
    /// runtime. Point host/port at your running phantom-server.
    @MainActor
    private static func makeViewModel() -> PhantomChatViewModel {
        let host = ProcessInfo.processInfo.environment["PHANTOM_DEMO_HOST"] ?? "127.0.0.1"
        let port = UInt16(ProcessInfo.processInfo.environment["PHANTOM_DEMO_PORT"] ?? "") ?? 4242

        // loadPinnedKey falls back to the documented dev hex if the bundled
        // phantom_server_pk.bin is still the placeholder; a real deployment bakes
        // the real key (see Sources/PhantomDemoKit/Resources/README.md).
        let pinnedKey = (try? PhantomServerConfig.loadPinnedKey()) ?? Data()
        let config = PhantomServerConfig(host: host, port: port, pinnedKey: pinnedKey)
        return PhantomChatViewModel(config: config)
    }
}

// MARK: - Root view

struct ContentView: View {
    @ObservedObject var viewModel: PhantomChatViewModel
    @State private var draft: String = ""
    @FocusState private var inputFocused: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                connectionBanner
                messageList
                Divider()
                inputBar
            }
            .navigationTitle("Phantom Chat")
            .navigationBarTitleDisplayModeInlineIfAvailable()
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    connectButton
                }
                ToolbarItem(placement: .secondaryActionIfAvailable) {
                    Button {
                        Task { await viewModel.reconnect() }
                    } label: {
                        Label("Reconnect (0-RTT)", systemImage: "arrow.clockwise")
                    }
                    .disabled(!viewModel.isConnected || viewModel.isBusy)
                }
                ToolbarItem(placement: .secondaryActionIfAvailable) {
                    Button {
                        Task { await viewModel.callMigrateAPI(to: "0.0.0.0:0") }
                    } label: {
                        Label("Call migrate() API (no-op over TCP)",
                              systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(!viewModel.isConnected || viewModel.isBusy)
                }
            }
        }
    }

    // MARK: Banner

    private var connectionBanner: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(bannerColor)
                .frame(width: 10, height: 10)
            Text(viewModel.statusText)
                .font(.footnote.weight(.medium))
                .lineLimit(1)
            Spacer()
            if viewModel.isBusy {
                ProgressView().controlSize(.small)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity)
        .background(bannerColor.opacity(0.15))
    }

    private var bannerColor: Color {
        switch viewModel.state {
        case .connected, .pqcReady:
            return .green
        case .classicalReady, .pqcUpgrading, .connecting:
            return .yellow
        case .migrating:
            return .orange
        case .failed, .dead:
            return .red
        case .closed:
            return .gray
        }
    }

    // MARK: Message list

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 8) {
                    ForEach(viewModel.messages) { message in
                        MessageRow(message: message)
                            .id(message.id)
                    }
                }
                .padding(16)
            }
            .onChange(of: viewModel.messages.count) { _ in
                if let last = viewModel.messages.last {
                    withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
        }
    }

    // MARK: Input bar

    private var inputBar: some View {
        HStack(spacing: 8) {
            TextField("Message", text: $draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .focused($inputFocused)
                .lineLimit(1...4)
                .disabled(!viewModel.isConnected)
                .onSubmit(sendDraft)

            Button(action: sendDraft) {
                Image(systemName: "paperplane.fill")
            }
            .disabled(!viewModel.isConnected ||
                      draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding(12)
    }

    private func sendDraft() {
        let text = draft
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        draft = ""
        Task { await viewModel.send(text) }
    }

    // MARK: Connect / disconnect toolbar button

    private var connectButton: some View {
        Group {
            if viewModel.isConnected {
                Button(role: .destructive) {
                    Task { await viewModel.disconnect() }
                } label: {
                    Label("Disconnect", systemImage: "bolt.slash")
                }
                .disabled(viewModel.isBusy)
            } else {
                Button {
                    Task { await viewModel.connect() }
                } label: {
                    Label("Connect", systemImage: "bolt")
                }
                .disabled(viewModel.isBusy)
            }
        }
    }
}

// MARK: - Message row

struct MessageRow: View {
    let message: ChatMessage

    var body: some View {
        switch message.origin {
        case .system:
            Text(message.text)
                .font(.caption.italic())
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .center)
        case .outbound:
            bubble(alignment: .trailing, color: .blue, textColor: .white)
        case .inbound:
            bubble(alignment: .leading, color: Color.gray.opacity(0.25), textColor: .primary)
        }
    }

    private func bubble(alignment: HorizontalAlignment, color: Color, textColor: Color) -> some View {
        HStack {
            if alignment == .trailing { Spacer(minLength: 40) }
            Text(message.text)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(color)
                .foregroundStyle(textColor)
                .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            if alignment == .leading { Spacer(minLength: 40) }
        }
    }
}

// MARK: - Cross-platform toolbar/title shims
//
// The sample's library targets build on macOS too (`swift build`), where some
// iOS-only modifiers/placements don't exist. These shims keep the single source
// compiling on both platforms.

private extension View {
    @ViewBuilder
    func navigationBarTitleDisplayModeInlineIfAvailable() -> some View {
        #if os(iOS)
        self.navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }
}

private extension ToolbarItemPlacement {
    /// `.secondaryAction` exists on both platforms in recent SDKs; alias kept for
    /// clarity and a single point of change.
    static var secondaryActionIfAvailable: ToolbarItemPlacement {
        .secondaryAction
    }
}
