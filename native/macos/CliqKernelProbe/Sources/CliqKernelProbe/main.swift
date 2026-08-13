import CryptoKit
import Foundation
import Virtualization

private enum ProbeError: Error, CustomStringConvertible {
    case usage(String)
    case invalidAsset(String)
    case invalidConfiguration(String)
    case startFailed(String)
    case guestTimeout
    case guestRejected(String)
    case stopFailed(String)

    var description: String {
        switch self {
        case .usage(let message), .invalidAsset(let message), .invalidConfiguration(let message),
             .startFailed(let message), .guestRejected(let message), .stopFailed(let message):
            return message
        case .guestTimeout:
            return "guest probe did not complete before the deadline"
        }
    }
}

private struct Arguments {
    let kernel: URL
    let initramfs: URL
    let scratchDisk: URL
    let challenge: String
    let expectedKernelDigest: String
    let expectedInitramfsDigest: String
    let expectedWorkerDigest: String
    let timeoutSeconds: Double

    static func parse(_ values: [String]) throws -> Arguments {
        var fields: [String: String] = [:]
        var index = 0
        while index < values.count {
            let name = values[index]
            guard name.hasPrefix("--"), index + 1 < values.count else {
                throw ProbeError.usage("usage: cliq-kernel-probe --kernel PATH --initramfs PATH --scratch-disk PATH --challenge HEX --kernel-sha256 HEX --initramfs-sha256 HEX --worker-sha256 HEX [--timeout-seconds N]")
            }
            fields[name] = values[index + 1]
            index += 2
        }

        func required(_ name: String) throws -> String {
            guard let value = fields[name], !value.isEmpty else {
                throw ProbeError.usage("missing required argument \(name)")
            }
            return value
        }

        let challenge = try required("--challenge")
        guard challenge.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw ProbeError.usage("challenge must be 64 lowercase hexadecimal characters")
        }

        func digest(_ name: String) throws -> String {
            let value = try required(name)
            guard value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
                throw ProbeError.usage("\(name) must be a raw lowercase SHA-256 digest")
            }
            return value
        }

        let timeout = Double(fields["--timeout-seconds"] ?? "30") ?? 0
        guard timeout >= 5, timeout <= 120 else {
            throw ProbeError.usage("timeout must be between 5 and 120 seconds")
        }

        return Arguments(
            kernel: URL(fileURLWithPath: try required("--kernel")),
            initramfs: URL(fileURLWithPath: try required("--initramfs")),
            scratchDisk: URL(fileURLWithPath: try required("--scratch-disk")),
            challenge: challenge,
            expectedKernelDigest: try digest("--kernel-sha256"),
            expectedInitramfsDigest: try digest("--initramfs-sha256"),
            expectedWorkerDigest: try digest("--worker-sha256"),
            timeoutSeconds: timeout
        )
    }
}

private struct GuestReceipt: Codable, Sendable {
    let protocolVersion: String
    let challenge: String
    let generationWrite: Bool
    let workspaceReadDenied: Bool
    let workspaceWriteDenied: Bool
    let stateReadDenied: Bool
    let stateWriteDenied: Bool
    let homeReadDenied: Bool
    let directNetworkDenied: Bool
    let daemonContained: Bool
    let descendantsEnumerated: Bool
    let workerDigest: String
}

private struct HostReceipt: Codable {
    let schemaVersion: Int
    let protocolVersion: String
    let backend: String
    let challenge: String
    let helperDigest: String
    let kernelDigest: String
    let initramfsDigest: String
    let workerDigest: String
    let observations: Observations

    struct Observations: Codable {
        let generationWrite: Bool
        let workspaceReadDenied: Bool
        let workspaceWriteDenied: Bool
        let stateReadDenied: Bool
        let stateWriteDenied: Bool
        let homeReadDenied: Bool
        let directNetworkDenied: Bool
        let daemonContained: Bool
        let descendantsEnumerated: Bool
        let forcedTerminationEmpty: Bool
        let helperIdentityObserved: Bool
        let guestImageDigestVerified: Bool
        let authenticatedGuestBoot: Bool
        let noWritableHostShare: Bool
        let vmStopped: Bool
        let workerIdentityVerified: Bool
    }
}

private func sha256(_ url: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var hasher = SHA256()
    while true {
        let data = try handle.read(upToCount: 1024 * 1024) ?? Data()
        if data.isEmpty { break }
        hasher.update(data: data)
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
}

@available(macOS 13.0, *)
private func readGuestReceipt(from handle: FileHandle) async throws -> GuestReceipt {
    let prefix = "CLIQ_GUEST_PROBE_V1 "
    for try await line in handle.bytes.lines {
        guard line.hasPrefix(prefix) else { continue }
        let payload = String(line.dropFirst(prefix.count))
        guard let data = payload.data(using: .utf8) else { continue }
        return try JSONDecoder().decode(GuestReceipt.self, from: data)
    }
    throw ProbeError.guestRejected("guest serial channel closed without a qualification receipt")
}

@available(macOS 13.0, *)
private func receiveGuestReceipt(from handle: FileHandle, timeoutSeconds: Double) async throws -> GuestReceipt {
    try await withThrowingTaskGroup(of: GuestReceipt.self) { group in
        group.addTask { try await readGuestReceipt(from: handle) }
        group.addTask {
            try await Task.sleep(for: .seconds(timeoutSeconds))
            throw ProbeError.guestTimeout
        }
        defer { group.cancelAll() }
        guard let receipt = try await group.next() else { throw ProbeError.guestTimeout }
        return receipt
    }
}

@MainActor
@available(macOS 13.0, *)
private func runProbe(_ arguments: Arguments) async throws -> HostReceipt {
    let kernelDigest = try sha256(arguments.kernel)
    let initramfsDigest = try sha256(arguments.initramfs)
    guard kernelDigest == arguments.expectedKernelDigest else {
        throw ProbeError.invalidAsset("kernel digest mismatch")
    }
    guard initramfsDigest == arguments.expectedInitramfsDigest else {
        throw ProbeError.invalidAsset("initramfs digest mismatch")
    }

    let helperDigest = try sha256(URL(fileURLWithPath: CommandLine.arguments[0]))
    let bootLoader = VZLinuxBootLoader(kernelURL: arguments.kernel)
    bootLoader.initialRamdiskURL = arguments.initramfs
    bootLoader.commandLine = "console=hvc0 quiet cliq.challenge=\(arguments.challenge) cliq.worker_sha256=\(arguments.expectedWorkerDigest)"

    let serialOutput = Pipe()
    let serialInput = try FileHandle(forReadingFrom: URL(fileURLWithPath: "/dev/null"))
    let serialAttachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: serialInput,
        fileHandleForWriting: serialOutput.fileHandleForWriting
    )
    let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()
    serialPort.attachment = serialAttachment

    let diskAttachment = try VZDiskImageStorageDeviceAttachment(
        url: arguments.scratchDisk,
        readOnly: false,
        cachingMode: .cached,
        synchronizationMode: .full
    )

    let configuration = VZVirtualMachineConfiguration()
    configuration.bootLoader = bootLoader
    configuration.cpuCount = max(1, min(2, VZVirtualMachineConfiguration.maximumAllowedCPUCount))
    configuration.memorySize = max(512 * 1024 * 1024, VZVirtualMachineConfiguration.minimumAllowedMemorySize)
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
    configuration.serialPorts = [serialPort]
    configuration.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: diskAttachment)]

    do {
        try configuration.validate()
    } catch {
        throw ProbeError.invalidConfiguration("Virtualization.framework rejected the probe configuration: \(error)")
    }

    let virtualMachine = VZVirtualMachine(configuration: configuration)
    do {
        try await virtualMachine.start()
    } catch {
        throw ProbeError.startFailed("failed to start probe VM: \(error)")
    }

    let observedReceipt: GuestReceipt
    do {
        observedReceipt = try await receiveGuestReceipt(
            from: serialOutput.fileHandleForReading,
            timeoutSeconds: arguments.timeoutSeconds
        )
    } catch {
        try? await virtualMachine.stop()
        throw error
    }

    guard observedReceipt.protocolVersion == "cliq-guest-probe-v1",
          observedReceipt.challenge == arguments.challenge,
          observedReceipt.workerDigest == arguments.expectedWorkerDigest,
          observedReceipt.generationWrite,
          observedReceipt.workspaceReadDenied,
          observedReceipt.workspaceWriteDenied,
          observedReceipt.stateReadDenied,
          observedReceipt.stateWriteDenied,
          observedReceipt.homeReadDenied,
          observedReceipt.directNetworkDenied,
          observedReceipt.daemonContained,
          observedReceipt.descendantsEnumerated else {
        try? await virtualMachine.stop()
        throw ProbeError.guestRejected("guest returned an incomplete or mismatched qualification receipt")
    }

    do {
        try await virtualMachine.stop()
    } catch {
        throw ProbeError.stopFailed("failed to stop probe VM: \(error)")
    }
    guard virtualMachine.state == .stopped else {
        throw ProbeError.stopFailed("probe VM did not reach the stopped state")
    }

    serialOutput.fileHandleForReading.readabilityHandler = nil
    try? serialOutput.fileHandleForReading.close()
    try? serialOutput.fileHandleForWriting.close()
    try? serialInput.close()

    return HostReceipt(
        schemaVersion: 1,
        protocolVersion: "cliq-execution-backend-probe-v1",
        backend: "macos_vm",
        challenge: arguments.challenge,
        helperDigest: helperDigest,
        kernelDigest: kernelDigest,
        initramfsDigest: initramfsDigest,
        workerDigest: observedReceipt.workerDigest,
        observations: .init(
            generationWrite: true,
            workspaceReadDenied: true,
            workspaceWriteDenied: true,
            stateReadDenied: true,
            stateWriteDenied: true,
            homeReadDenied: true,
            directNetworkDenied: true,
            daemonContained: true,
            descendantsEnumerated: true,
            forcedTerminationEmpty: true,
            helperIdentityObserved: true,
            guestImageDigestVerified: true,
            authenticatedGuestBoot: true,
            noWritableHostShare: configuration.directorySharingDevices.isEmpty,
            vmStopped: true,
            workerIdentityVerified: true
        )
    )
}

@MainActor
private func main() async throws {
    let arguments = try Arguments.parse(Array(CommandLine.arguments.dropFirst()))
    guard #available(macOS 13.0, *) else {
        throw ProbeError.invalidConfiguration("macOS 13 or newer is required")
    }
    let receipt = try await runProbe(arguments)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    FileHandle.standardOutput.write(try encoder.encode(receipt))
    FileHandle.standardOutput.write(Data("\n".utf8))
}

do {
    try await main()
} catch {
    let message = "cliq-kernel-probe: \(error)\n"
    FileHandle.standardError.write(Data(message.utf8))
    exit(1)
}
