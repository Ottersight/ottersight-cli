import which from "which";

export async function checkDependencies(): Promise<void> {
  const missing: string[] = [];

  for (const bin of ["syft", "grype"]) {
    const found = await which(bin, { nothrow: true });
    if (!found) missing.push(bin);
  }

  if (missing.length === 0) return;

  for (const bin of missing) {
    console.error(`\n\u2717 ${bin} not found. Install it first:`);
    if (bin === "syft") {
      console.error("  brew install anchore/grype/syft            (macOS)");
      console.error(
        "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh"
      );
    }
    if (bin === "grype") {
      console.error("  brew install anchore/grype/grype           (macOS)");
      console.error(
        "  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh"
      );
    }
  }
  process.exit(1);
}
