class Onyx < Formula
  desc "Lightweight command guard for Linux servers"
  homepage "https://ttr1563.github.io/onyx/"
  url "https://github.com/ttr1563/onyx/releases/download/v0.1.0/onyx-0.1.0.tar.gz"
  sha256 "c5deba7be4a73d56fd3fd866798707bbf094852dad320ddc703a28db4e670359"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "onyx 0.1.0", shell_output("#{bin}/onyx --version")
    output = shell_output("#{bin}/onyx check -- rm -rf /example", 77)
    assert_match "destructive-recursive-delete", output
  end
end
