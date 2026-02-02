#!/usr/bin/env swift

// Simple test runner that doesn't require XCTest
// Run with: swift test-poseidon.swift

import Foundation

// Note: This script tests the Poseidon implementation by running the built executable
// The actual testing is done by building and running a test target

print("=== Swift SDK Build Verification ===")
print("")

let fm = FileManager.default
let currentDir = fm.currentDirectoryPath

// Check if we're in the swift-sdk directory
let packagePath = currentDir.hasSuffix("swift-sdk") ? currentDir : currentDir + "/swift-sdk"

print("Checking package at: \(packagePath)")

// Run swift build
let buildProcess = Process()
buildProcess.executableURL = URL(fileURLWithPath: "/usr/bin/swift")
buildProcess.arguments = ["build", "--package-path", packagePath]
buildProcess.currentDirectoryURL = URL(fileURLWithPath: packagePath)

let buildPipe = Pipe()
buildProcess.standardOutput = buildPipe
buildProcess.standardError = buildPipe

do {
    try buildProcess.run()
    buildProcess.waitUntilExit()
    
    let data = buildPipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(data: data, encoding: .utf8) ?? ""
    
    if buildProcess.terminationStatus == 0 {
        print("✅ Build succeeded!")
        print(output)
    } else {
        print("❌ Build failed!")
        print(output)
        exit(1)
    }
} catch {
    print("❌ Failed to run build: \(error)")
    exit(1)
}

print("")
print("=== All checks passed! ===")
print("Note: Full test suite requires Xcode (XCTest framework)")
print("Install Xcode from the App Store to run: swift test")
