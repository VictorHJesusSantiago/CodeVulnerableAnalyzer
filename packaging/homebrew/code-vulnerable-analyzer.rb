class CodeVulnerableAnalyzer < Formula
  include Language::Python::Virtualenv
  desc "Analisador estático multi-linguagem, IaC e segredos"
  homepage "https://example.invalid/code-vulnerable-analyzer"
  url "https://example.invalid/code-vulnerable-analyzer-2.0.0.tar.gz"
  version "2.0.0"
  sha256 "SUBSTITUIR_PELO_SHA256_DO_RELEASE"
  depends_on "python@3.13"
  def install
    virtualenv_install_with_resources
  end
  test do
    system bin/"vulnscan", "--version"
  end
end
