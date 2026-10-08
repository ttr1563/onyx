class Onyx < Formula
  desc "Lightweight command guard for Linux servers"
  homepage "https://ttr1563.github.io/onyx/"
  url "https://github.com/ttr1563/onyx/releases/download/v0.1.2/onyx-0.1.2.tar.gz"
  sha256 "00a181a391af47b1560621cf01ebebcda9c1100b2f1f39f0ac0ff03c94d180c4"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "onyx 0.1.2", shell_output("#{bin}/onyx --version")
    output = shell_output("#{bin}/onyx check -- rm -rf /example", 77)
    assert_match "destructive-recursive-delete", output
  end
end
