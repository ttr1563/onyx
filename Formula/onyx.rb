class Onyx < Formula
  desc "Lightweight command guard for Linux servers"
  homepage "https://ttr1563.github.io/onyx/"
  url "https://github.com/ttr1563/onyx/releases/download/v0.1.3/onyx-0.1.3.tar.gz"
  sha256 "d50cd57262b51c39e741300b11c2901be0262575cd25746eb5e830d3abe68ff4"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "onyx 0.1.3", shell_output("#{bin}/onyx --version")
    output = shell_output("#{bin}/onyx check -- rm -rf /example", 77)
    assert_match "destructive-recursive-delete", output
  end
end
