import type { Doc } from "../_generated/dataModel";

export type PackageScanStatus = Doc<"packages">["scanStatus"];

type PackageReleaseSecurityLike = Pick<
  Doc<"packageReleases">,
  "sha256hash" | "vtAnalysis" | "llmAnalysis" | "verification" | "staticScan" | "manualModeration"
>;

export function normalizePackageScanStatus(status: string | null | undefined): PackageScanStatus {
  const normalized = status?.trim().toLowerCase();
  switch (normalized) {
    case "benign":
      return "clean";
    case "clean":
    case "suspicious":
    case "malicious":
    case "pending":
    case "not-run":
      return normalized as PackageScanStatus;
    default:
      return undefined;
  }
}

export function resolvePackageReleaseScanStatus(
  release: PackageReleaseSecurityLike,
): Exclude<PackageScanStatus, undefined> {
  if (release.manualModeration?.state === "approved") return "clean";
  if (
    release.manualModeration?.state === "quarantined" ||
    release.manualModeration?.state === "revoked"
  ) {
    return "malicious";
  }

  const staticStatus = normalizePackageScanStatus(release.staticScan?.status);
  if (staticStatus === "malicious") return "malicious";

  const vtStatus = normalizePackageScanStatus(release.vtAnalysis?.status);
  if (vtStatus === "malicious") return "malicious";

  const llmStatus = normalizePackageScanStatus(
    release.llmAnalysis?.verdict ?? release.llmAnalysis?.status,
  );
  if (llmStatus === "malicious") return "malicious";
  if (llmStatus === "suspicious") return "suspicious";
  if (llmStatus === "clean") return "clean";

  if (vtStatus === "suspicious") return "suspicious";

  const verificationStatus = normalizePackageScanStatus(release.verification?.scanStatus);
  const effectiveVerificationStatus =
    verificationStatus === "suspicious" && staticStatus === "suspicious"
      ? undefined
      : verificationStatus;
  if (effectiveVerificationStatus === "malicious") return "malicious";
  if (effectiveVerificationStatus === "suspicious") return "suspicious";

  if (vtStatus) return vtStatus;
  if (effectiveVerificationStatus && effectiveVerificationStatus !== "not-run") {
    return effectiveVerificationStatus;
  }
  if (release.sha256hash) return "pending";

  return effectiveVerificationStatus ?? "not-run";
}

export function isPackageBlockedFromPublic(scanStatus: PackageScanStatus) {
  return scanStatus === "malicious";
}

export function getPackageDownloadSecurityBlock(release: PackageReleaseSecurityLike) {
  if (release.manualModeration?.state === "quarantined") {
    return {
      status: 403,
      message: "Blocked: this package release is quarantined by ClawHub moderation.",
    };
  }

  if (release.manualModeration?.state === "revoked") {
    return {
      status: 403,
      message: "Blocked: this package release has been revoked by ClawHub moderation.",
    };
  }

  const scanStatus = resolvePackageReleaseScanStatus(release);

  if (scanStatus === "malicious") {
    return {
      status: 403,
      message:
        "Blocked: this package release has been flagged as malicious and cannot be downloaded.",
    };
  }

  return null;
}
