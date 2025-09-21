# DNS Benchmark Tool 🚀

A simple tool to test and compare DNS servers performance, including DNS over TLS (DoT) support.

## Features

- Test 20+ preconfigured DNS servers (Cloudflare, Google, Quad9, etc.)
- Support for DNS over TLS (encrypted DNS)
- Detailed statistics (average, min, max, P95, P99)
- Export results to CSV and JSON

## Installation

```bash
# Install dependencies
# Ubuntu/Debian
sudo apt-get install dnsutils knot-dnsutils

# Fedora/RHEL  
sudo dnf install bind-utils knot-utils

# macOS
brew install knot

# Clone repo
git clone https://github.com/fernandorubio/dns-benchmark-tool.git
cd dns-benchmark-tool
chmod +x dns_benchmark.py
```

## Usage

```bash
# Basic usage (tests google.com)
./dns_benchmark.py

# Test specific domain
./dns_benchmark.py example.com

# More iterations for better accuracy
./dns_benchmark.py -i 10

# Test only encrypted DNS (DoT)
./dns_benchmark.py --only-dot

# Test only traditional DNS
./dns_benchmark.py --only-dns

# Add custom DNS server
./dns_benchmark.py -s MyDNS:192.168.1.1
```

## Output

The tool creates two files:
- `dns_benchmark_TIMESTAMP.json` - Complete results with all data
- `dns_benchmark_TIMESTAMP.csv` - For Excel/LibreOffice analysis

## Results Explanation

- **Average (avg_ms)**: Average response time
- **P95**: 95% of queries are faster than this
- **Success Rate**: Percentage of successful queries
- **StDev**: Lower = more consistent

### What's Good?
- Average < 30ms = Excellent
- P95 < 100ms = Good
- Success Rate > 99% = Reliable

## License

MIT

## Author

Made with ❤️ for the community