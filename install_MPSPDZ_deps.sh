if [[ "$(uname -s)" == "Darwin" ]]; then
    brew install automake cmake git llvm boost gmp ntl libsodium openssl libtool python
elif [[ -f /etc/os-release ]] && grep -qi ubuntu /etc/os-release; then
  sudo apt-get update && sudo apt-get install -y automake build-essential clang cmake git libboost-dev libboost-filesystem-dev libboost-iostreams-dev libboost-thread-dev libgmp-dev libntl-dev libsodium-dev libssl-dev libtool python3
else
  echo "Unsupported OS: only Ubuntu and macOS are handled." >&2
  exit 1
fi