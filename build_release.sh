#!/bin/bash

# AngryEther Release Build Script
# Builds optimized binary and creates compressed release archive

set -e  # Exit on any error

PROJECT_NAME="angryether"
VERSION=$(grep '^version' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
RELEASE_NAME="${PROJECT_NAME}-v${VERSION}-${OS}-${ARCH}"
RELEASE_DIR="release"
ARCHIVE_NAME="${RELEASE_NAME}.tar.gz"

echo "Building AngryEther Release v${VERSION} for ${OS}-${ARCH}"
echo "=================================================="

# Clean previous builds
echo "Cleaning previous builds..."
cargo clean
rm -rf ${RELEASE_DIR}

# Build optimized release binary
echo "Building optimized release binary..."
cargo build --release

# Create release directory structure
echo "Creating release package..."
mkdir -p ${RELEASE_DIR}/${RELEASE_NAME}

# Copy binary
cp target/release/${PROJECT_NAME} ${RELEASE_DIR}/${RELEASE_NAME}/

# Copy essential files
cp README.md ${RELEASE_DIR}/${RELEASE_NAME}/
cp -r ports/ ${RELEASE_DIR}/${RELEASE_NAME}/

# Create installation script
cat > ${RELEASE_DIR}/${RELEASE_NAME}/install.sh << 'EOF'
#!/bin/bash

# AngryEther Installation Script

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/usr/local/share/angryether"

echo "Installing AngryEther..."

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# Install binary
cp angryether ${INSTALL_DIR}/
chmod +x ${INSTALL_DIR}/angryether

# Install configuration files
mkdir -p ${CONFIG_DIR}
cp -r ports/ ${CONFIG_DIR}/

echo "AngryEther installed successfully!"
echo "Usage: sudo angryether --help"
echo "Default ports file: ${CONFIG_DIR}/ports/10000.txt"
EOF

chmod +x ${RELEASE_DIR}/${RELEASE_NAME}/install.sh

# Create uninstall script  
cat > ${RELEASE_DIR}/${RELEASE_NAME}/uninstall.sh << 'EOF'
#!/bin/bash

# AngryEther Uninstallation Script

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/usr/local/share/angryether"

echo "Uninstalling AngryEther..."

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Remove binary and config
rm -f ${INSTALL_DIR}/angryether
rm -rf ${CONFIG_DIR}

echo "AngryEther uninstalled successfully!"
EOF

chmod +x ${RELEASE_DIR}/${RELEASE_NAME}/uninstall.sh

# Create usage examples
cat > ${RELEASE_DIR}/${RELEASE_NAME}/EXAMPLES.md << 'EOF'
# AngryEther Usage Examples

## Basic Scanning
```bash
# Default scan (ICMP + TCP ping)
sudo angryether

# List available interfaces
angryether --interfaces

# Scan specific interface
sudo angryether -i eth0
```

## Host Discovery Methods
```bash
# Add ARP scanning for better coverage
sudo angryether --arp

# ARP-only (fastest for local networks)
sudo angryether --arp-only

# Custom timeout for slow networks
sudo angryether -t 2000 --arp
```

## Output Options
```bash
# Save results to JSON
sudo angryether -j scan_results.json

# Complete scan with all options
sudo angryether --arp -t 1000 -j detailed_scan.json
```

## Performance Tips
- Use `--arp-only` for fastest local network scanning
- Increase timeout (`-t`) for wireless or slow networks  
- ARP scanning requires root privileges
- JSON output is ideal for automation and reporting
EOF

# Create release info
cat > ${RELEASE_DIR}/${RELEASE_NAME}/RELEASE_INFO.txt << EOF
AngryEther Network Scanner
Version: ${VERSION}
Architecture: ${OS}-${ARCH}
Build Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Git Commit: $(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

Features:
- Multi-method host discovery (ICMP, TCP, ARP)
- Lightning-fast ARP scanning (100-200x faster)
- Intelligent port scanning with banner grabbing
- JSON export for automation
- Cross-platform support

Requirements:
- Administrator/root privileges for ICMP and ARP scanning
- Network interface access

Installation:
Run: sudo ./install.sh

For support and documentation:
https://github.com/pg3uk/AngryEtherRust
EOF

# Create compressed archive
echo "Creating compressed archive..."
cd ${RELEASE_DIR}
tar -czf ${ARCHIVE_NAME} ${RELEASE_NAME}/
cd ..

# Generate checksums
echo "Generating checksums..."
cd ${RELEASE_DIR}
sha256sum ${ARCHIVE_NAME} > ${ARCHIVE_NAME}.sha256
md5sum ${ARCHIVE_NAME} > ${ARCHIVE_NAME}.md5
cd ..

# Display results
echo ""
echo "Release build completed successfully!"
echo "=================================="
echo "Archive: ${RELEASE_DIR}/${ARCHIVE_NAME}"
echo "Size: $(du -h ${RELEASE_DIR}/${ARCHIVE_NAME} | cut -f1)"
echo "Binary size: $(du -h target/release/${PROJECT_NAME} | cut -f1)"
echo ""
echo "Contents:"
echo "- angryether (optimized binary)"
echo "- README.md (documentation)"  
echo "- ports/ (default port configurations)"
echo "- install.sh (system installation script)"
echo "- uninstall.sh (removal script)"
echo "- EXAMPLES.md (usage examples)"
echo "- RELEASE_INFO.txt (build information)"
echo ""
echo "Checksums generated:"
echo "- SHA256: ${RELEASE_DIR}/${ARCHIVE_NAME}.sha256"
echo "- MD5: ${RELEASE_DIR}/${ARCHIVE_NAME}.md5"
echo ""
echo "To extract: tar -xzf ${RELEASE_DIR}/${ARCHIVE_NAME}"
echo "To install: cd ${RELEASE_NAME} && sudo ./install.sh"
