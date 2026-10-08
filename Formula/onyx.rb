class Onyx < Formula
  desc "Lightweight command guard for Linux servers"
  homepage "https://ttr1563.github.io/onyx/"
  url "https://github.com/ttr1563/onyx/releases/download/v0.1.1/onyx-0.1.1.tar.gz"
  sha256 "61d355c76c2770375602485dee50dd648f3257f825fd03818cfa0b729daaf820"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "onyx 0.1.1", shell_output("#{bin}/onyx --version")
    output = shell_output("#{bin}/onyx check -- rm -rf /example", 77)
    assert_match "destructive-recursive-delete", output
  end
end
