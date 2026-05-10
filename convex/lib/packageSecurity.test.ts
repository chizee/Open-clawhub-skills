import { describe, expect, it } from "vitest";
import {
  getPackageDownloadSecurityBlock,
  isPackageBlockedFromPublic,
  resolvePackageReleaseScanStatus,
} from "./packageSecurity";

describe("packageSecurity", () => {
  it("treats pending package scans as public", () => {
    expect(isPackageBlockedFromPublic("pending")).toBe(false);
  });

  it("allows package downloads while VT is pending", () => {
    expect(
      getPackageDownloadSecurityBlock({
        sha256hash: "a".repeat(64),
      } as never),
    ).toBeNull();
  });

  it("still resolves sha256-only releases to pending", () => {
    expect(
      resolvePackageReleaseScanStatus({
        sha256hash: "a".repeat(64),
      } as never),
    ).toBe("pending");
  });

  it("still blocks malicious package releases", () => {
    expect(isPackageBlockedFromPublic("malicious")).toBe(true);
    expect(
      getPackageDownloadSecurityBlock({
        vtAnalysis: { status: "malicious" },
      } as never),
    ).toEqual(
      expect.objectContaining({
        status: 403,
      }),
    );
  });

  it("does not let suspicious static scans override clean verification", () => {
    expect(
      resolvePackageReleaseScanStatus({
        staticScan: { status: "suspicious" },
        verification: { scanStatus: "clean" },
      } as never),
    ).toBe("clean");
  });

  it("does not preserve old static-only suspicious verification", () => {
    expect(
      resolvePackageReleaseScanStatus({
        staticScan: { status: "suspicious" },
        verification: { scanStatus: "suspicious" },
        sha256hash: "a".repeat(64),
      } as never),
    ).toBe("pending");
  });

  it("lets package ClawScan clear non-malicious scanner noise", () => {
    expect(
      resolvePackageReleaseScanStatus({
        vtAnalysis: { status: "suspicious" },
        llmAnalysis: { status: "completed", verdict: "benign" },
        verification: { scanStatus: "suspicious" },
      } as never),
    ).toBe("clean");
  });

  it("lets manual package moderation approve or block releases", () => {
    expect(
      resolvePackageReleaseScanStatus({
        staticScan: { status: "malicious" },
        manualModeration: { state: "approved" },
      } as never),
    ).toBe("clean");

    expect(
      getPackageDownloadSecurityBlock({
        verification: { scanStatus: "clean" },
        manualModeration: { state: "quarantined" },
      } as never),
    ).toEqual(
      expect.objectContaining({
        status: 403,
        message: expect.stringContaining("quarantined"),
      }),
    );
  });
});
