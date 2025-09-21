#!/usr/bin/env python3
import subprocess
import time
import statistics
import json
import csv
import argparse
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import sys
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed

# Version
__version__ = "1.0.0"

# Colors for terminal output
class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class DNSServer:
    """Represents a DNS server configuration and test results"""

    def __init__(self, name: str, server: str, tls_host: str = None, use_tls: bool = True):
        self.name = name
        self.server = server
        self.tls_host = tls_host
        self.use_tls = use_tls and tls_host is not None
        self.results = []
        self.stats = {}
        self.test_completed = False

class DNSBenchmark:
    """Main DNS Benchmark class"""

    def __init__(self, domain: str, iterations: int = 5, timeout: int = 5, parallel: bool = False):
        self.domain = domain
        self.iterations = iterations
        self.timeout = timeout
        self.parallel = parallel
        self.servers = self._initialize_servers()
        self.results = {}
        self.start_time = None
        self.end_time = None

    def _initialize_servers(self) -> List[DNSServer]:
        """Initialize the list of DNS servers to test"""
        servers = [
            # DNS over TLS (DoT) servers
            DNSServer("Cloudflare-DoT", "1.1.1.1", "cloudflare-dns.com"),
            DNSServer("Cloudflare-2-DoT", "1.0.0.1", "cloudflare-dns.com"),
            DNSServer("Google-DoT", "8.8.8.8", "dns.google"),
            DNSServer("Google-2-DoT", "8.8.4.4", "dns.google"),
            DNSServer("Quad9-DoT", "9.9.9.9", "dns.quad9.net"),
            DNSServer("Quad9-2-DoT", "149.112.112.112", "dns.quad9.net"),
            DNSServer("AdGuard-DoT", "94.140.14.14", "dns.adguard-dns.com"),
            DNSServer("AdGuard-2-DoT", "94.140.15.15", "dns.adguard-dns.com"),
            DNSServer("OpenDNS-DoT", "208.67.222.222", "dns.opendns.com"),
            DNSServer("dns4.eu-1-DoT", "86.54.11.100", "unfiltered.joindns4.eu"),
            DNSServer("dns4.eu-2-DoT", "86.54.11.200", "unfiltered.joindns4.eu"),
            DNSServer("dns0.eu-1-DoT", "193.110.81.0", "dns0.eu"),
            DNSServer("dns0.eu-2-DoT", "185.253.5.0", "dns0.eu"),

            # Traditional DNS servers (no encryption)
            DNSServer("Cloudflare", "1.1.1.1", use_tls=False),
            DNSServer("Cloudflare-2", "1.0.0.1", use_tls=False),
            DNSServer("Google", "8.8.8.8", use_tls=False),
            DNSServer("Google-2", "8.8.4.4", use_tls=False),
            DNSServer("Quad9", "9.9.9.9", use_tls=False),
            DNSServer("Quad9-2", "149.112.112.112", use_tls=False),
            DNSServer("OpenDNS", "208.67.222.222", use_tls=False),
            DNSServer("OpenDNS-2", "208.67.220.220", use_tls=False),
            DNSServer("Level3", "4.2.2.1", use_tls=False),
            DNSServer("Level3-2", "4.2.2.2", use_tls=False),
            DNSServer("Comodo", "8.26.56.26", use_tls=False)
        ]

        return servers

    def _run_dns_query(self, server: DNSServer) -> Tuple[bool, float, str]:
        """
        Execute a DNS query and return (success, time_ms, answer)
        """
        try:
            if server.use_tls:
                # Use kdig for DNS over TLS
                cmd = [
                    'kdig',
                    '+tls',
                    f'@{server.server}',
                    f'+tls-host={server.tls_host}',
                    self.domain,
                    '+stats',
                    '+nocomments',
                    '+retry=0'
                ]
            else:
                # Use dig for traditional DNS
                cmd = [
                    'dig',
                    f'@{server.server}',
                    self.domain,
                    '+stats',
                    '+nocomments',
                    '+retry=0',
                    f'+time={self.timeout}'
                ]

            start_time = time.perf_counter()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            end_time = time.perf_counter()

            if result.returncode != 0:
                return False, 0, "Query failed"

            # Extract query time from output
            output = result.stdout
            query_time = None

            # Look for query time in output
            for line in output.split('\n'):
                if 'Query time:' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'time:' and i + 1 < len(parts):
                            try:
                                query_time = float(parts[i + 1])
                                break
                            except ValueError:
                                continue

            # If we couldn't find the time in output, use measured time
            if query_time is None:
                query_time = (end_time - start_time) * 1000  # Convert to ms

            # Extract answer (IP address)
            answer = ""
            for line in output.split('\n'):
                if '\tIN\tA\t' in line or '\tIN\tAAAA\t' in line:
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        answer = parts[-1]
                        break

            return True, query_time, answer

        except subprocess.TimeoutExpired:
            return False, self.timeout * 1000, "Timeout"
        except FileNotFoundError:
            return False, 0, "Command not found"
        except Exception as e:
            return False, 0, str(e)

    def test_server(self, server: DNSServer, verbose: bool = True) -> Dict:
        """
        Run multiple tests on a DNS server
        """
        if verbose and not self.parallel:
            print(f"\n{Colors.CYAN}Testing {server.name} ({server.server})...{Colors.ENDC}")

        times = []
        successes = 0
        failures = 0
        first_answer = ""
        errors = []

        for i in range(self.iterations):
            success, query_time, answer = self._run_dns_query(server)

            if success and query_time > 0:
                times.append(query_time)
                successes += 1
                if i == 0:
                    first_answer = answer

                if verbose and not self.parallel:
                    # Color based on response time
                    if query_time < 20:
                        time_color = Colors.GREEN
                    elif query_time < 50:
                        time_color = Colors.YELLOW
                    else:
                        time_color = Colors.RED

                    print(f"  [{i+1}/{self.iterations}] {Colors.GREEN}✓{Colors.ENDC} "
                          f"{time_color}{query_time:.1f}ms{Colors.ENDC}")
            else:
                failures += 1
                errors.append(answer)
                if verbose and not self.parallel:
                    print(f"  [{i+1}/{self.iterations}] {Colors.RED}✗{Colors.ENDC} {answer}")

            # Small delay between queries to avoid flooding
            if i < self.iterations - 1:
                time.sleep(0.1)

        # Calculate statistics
        if times:
            sorted_times = sorted(times)
            server.stats = {
                'success_rate': (successes / self.iterations) * 100,
                'successes': successes,
                'failures': failures,
                'min': min(times),
                'max': max(times),
                'avg': statistics.mean(times),
                'median': statistics.median(times),
                'stdev': statistics.stdev(times) if len(times) > 1 else 0,
                'p95': sorted_times[int(len(sorted_times) * 0.95) - 1] if len(times) > 1 else sorted_times[0],
                'p99': sorted_times[int(len(sorted_times) * 0.99) - 1] if len(times) > 2 else sorted_times[-1],
                'answer': first_answer,
                'protocol': 'DoT' if server.use_tls else 'DNS'
            }
        else:
            server.stats = {
                'success_rate': 0,
                'successes': 0,
                'failures': failures,
                'min': 9999,
                'max': 9999,
                'avg': 9999,
                'median': 9999,
                'stdev': 0,
                'p95': 9999,
                'p99': 9999,
                'answer': "No response",
                'protocol': 'DoT' if server.use_tls else 'DNS'
            }

        server.results = times
        server.test_completed = True

        if self.parallel:
            print(f"{Colors.GREEN}✓{Colors.ENDC} Completed: {server.name}")

        return server.stats

    def run_benchmark(self, test_servers: Optional[List[str]] = None):
        """
        Execute the complete benchmark
        """
        self.start_time = datetime.now()

        # Print header
        print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'DNS Performance Benchmark':^70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'Version ' + __version__:^70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"Domain: {Colors.YELLOW}{self.domain}{Colors.ENDC}")
        print(f"Iterations per server: {Colors.YELLOW}{self.iterations}{Colors.ENDC}")
        print(f"Timeout: {Colors.YELLOW}{self.timeout}s{Colors.ENDC}")
        print(f"Parallel testing: {Colors.YELLOW}{'Yes' if self.parallel else 'No'}{Colors.ENDC}")

        # Filter servers if specified
        servers_to_test = self.servers
        if test_servers:
            servers_to_test = [s for s in self.servers
                               if any(name in s.name for name in test_servers)]

        print(f"Testing {len(servers_to_test)} DNS servers...")

        if self.parallel:
            # Parallel testing
            print(f"\n{Colors.CYAN}Starting parallel tests...{Colors.ENDC}")
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(self.test_server, server, False): server
                           for server in servers_to_test}

                for future in as_completed(futures):
                    server = futures[future]
                    try:
                        server.stats = future.result()
                        self.results[server.name] = server.stats
                    except Exception as e:
                        print(f"{Colors.RED}Error testing {server.name}: {e}{Colors.ENDC}")
        else:
            # Sequential testing
            for server in servers_to_test:
                self.test_server(server)
                self.results[server.name] = server.stats

        self.end_time = datetime.now()

        # Print results
        self.print_results(servers_to_test)
        self.print_ranking(servers_to_test)
        self.print_comparison()
        self.print_summary()
        self.save_results()

    def print_results(self, servers: List[DNSServer]):
        """
        Print detailed results
        """
        print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'Detailed Results':^70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")

        for server in servers:
            if not server.test_completed:
                continue

            stats = server.stats
            if stats['avg'] == 9999:
                print(f"\n{Colors.RED}❌ {server.name}{Colors.ENDC}")
                print(f"   All queries failed")
            else:
                # Determine color and emoji based on performance
                if stats['avg'] < 20:
                    color = Colors.GREEN
                    emoji = "🚀"
                elif stats['avg'] < 50:
                    color = Colors.YELLOW
                    emoji = "✓"
                else:
                    color = Colors.RED
                    emoji = "⚠"

                print(f"\n{color}{emoji} {server.name}{Colors.ENDC}")
                print(f"   Protocol: {stats['protocol']}")
                print(f"   Success Rate: {stats['success_rate']:.1f}% ({stats['successes']}/{self.iterations})")
                print(f"   Response Times (ms):")
                print(f"     Min:    {Colors.GREEN}{stats['min']:8.1f}{Colors.ENDC}")
                print(f"     Avg:    {Colors.YELLOW}{stats['avg']:8.1f}{Colors.ENDC}")
                print(f"     Median: {Colors.CYAN}{stats['median']:8.1f}{Colors.ENDC}")
                print(f"     P95:    {stats['p95']:8.1f}")
                print(f"     P99:    {stats['p99']:8.1f}")
                print(f"     Max:    {Colors.RED}{stats['max']:8.1f}{Colors.ENDC}")

                if stats['stdev'] > 0:
                    if stats['stdev'] < 10:
                        consistency = "Stable"
                        consistency_color = Colors.GREEN
                    elif stats['stdev'] < 30:
                        consistency = "Variable"
                        consistency_color = Colors.YELLOW
                    else:
                        consistency = "Unstable"
                        consistency_color = Colors.RED

                    print(f"     StDev:  {stats['stdev']:8.1f} "
                          f"({consistency_color}{consistency}{Colors.ENDC})")

    def print_ranking(self, servers: List[DNSServer]):
        """
        Print the final ranking
        """
        print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'Final Ranking (by average response time)':^70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")

        # Filter servers that responded and sort
        valid_servers = [s for s in servers if s.test_completed and s.stats['avg'] < 9999]
        sorted_servers = sorted(valid_servers, key=lambda s: s.stats['avg'])

        if not sorted_servers:
            print(f"{Colors.RED}No servers responded successfully!{Colors.ENDC}")
            return

        print(f"\n{'Rank':<6} {'Server':<20} {'Protocol':<10} {'Avg(ms)':<10} {'P95(ms)':<10} {'Success'}")
        print("-" * 70)

        for i, server in enumerate(sorted_servers, 1):
            stats = server.stats

            # Color and medal based on position
            if i == 1:
                color = Colors.GREEN + Colors.BOLD
                medal = "🥇"
            elif i == 2:
                color = Colors.GREEN
                medal = "🥈"
            elif i == 3:
                color = Colors.CYAN
                medal = "🥉"
            elif i <= 5:
                color = Colors.YELLOW
                medal = "  "
            else:
                color = Colors.ENDC
                medal = "  "

            print(f"{color}{medal}{i:<4} {server.name:<20} {stats['protocol']:<10} "
                  f"{stats['avg']:<10.1f} {stats['p95']:<10.1f} {stats['success_rate']:>6.0f}%{Colors.ENDC}")

        # Show winner
        if sorted_servers:
            winner = sorted_servers[0]
            print(f"\n{Colors.GREEN}{Colors.BOLD}🏆 WINNER: {winner.name}")
            print(f"   Protocol: {winner.stats['protocol']}")
            print(f"   Average: {winner.stats['avg']:.1f}ms | P95: {winner.stats['p95']:.1f}ms")
            print(f"   {winner.stats['success_rate']:.0f}% success rate{Colors.ENDC}")

    def print_comparison(self):
        """
        Compare DoT vs traditional DNS
        """
        dot_servers = [s for s in self.servers
                       if s.test_completed and s.use_tls and s.stats.get('avg', 9999) < 9999]
        dns_servers = [s for s in self.servers
                       if s.test_completed and not s.use_tls and s.stats.get('avg', 9999) < 9999]

        if dot_servers and dns_servers:
            print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'Protocol Comparison':^70}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")

            # Calculate averages
            avg_dot = statistics.mean([s.stats['avg'] for s in dot_servers])
            avg_dns = statistics.mean([s.stats['avg'] for s in dns_servers])
            p95_dot = statistics.mean([s.stats['p95'] for s in dot_servers])
            p95_dns = statistics.mean([s.stats['p95'] for s in dns_servers])
            success_dot = statistics.mean([s.stats['success_rate'] for s in dot_servers])
            success_dns = statistics.mean([s.stats['success_rate'] for s in dns_servers])

            print(f"\n{Colors.CYAN}DNS over TLS (DoT):{Colors.ENDC}")
            print(f"  Servers tested: {len(dot_servers)}")
            print(f"  Average response: {avg_dot:.1f}ms")
            print(f"  Average P95: {p95_dot:.1f}ms")
            print(f"  Average success rate: {success_dot:.1f}%")

            print(f"\n{Colors.CYAN}Traditional DNS:{Colors.ENDC}")
            print(f"  Servers tested: {len(dns_servers)}")
            print(f"  Average response: {avg_dns:.1f}ms")
            print(f"  Average P95: {p95_dns:.1f}ms")
            print(f"  Average success rate: {success_dns:.1f}%")

            diff = avg_dot - avg_dns
            if diff > 0:
                print(f"\n{Colors.YELLOW}→ Traditional DNS is {diff:.1f}ms faster on average{Colors.ENDC}")
                print(f"{Colors.BLUE}→ DoT provides encryption at a {diff:.1f}ms latency cost{Colors.ENDC}")
            else:
                print(f"\n{Colors.GREEN}→ DoT is {abs(diff):.1f}ms faster on average{Colors.ENDC}")
                print(f"{Colors.GREEN}→ DoT provides both encryption AND better performance!{Colors.ENDC}")

    def print_summary(self):
        """
        Print test summary
        """
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
            print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'Test Summary':^70}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
            print(f"Total test duration: {duration:.1f} seconds")
            print(f"Total queries performed: {len(self.servers) * self.iterations}")

            successful_servers = sum(1 for s in self.servers
                                     if s.test_completed and s.stats.get('avg', 9999) < 9999)
            print(f"Successful servers: {successful_servers}/{len(self.servers)}")

    def save_results(self):
        """
        Save results to JSON and CSV files
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON
        json_filename = f"dns_benchmark_{timestamp}.json"
        data = {
            'version': __version__,
            'timestamp': timestamp,
            'domain': self.domain,
            'iterations': self.iterations,
            'timeout': self.timeout,
            'test_duration': (self.end_time - self.start_time).total_seconds() if self.end_time else 0,
            'results': {}
        }

        for server in self.servers:
            if server.test_completed:
                data['results'][server.name] = {
                    'server': server.server,
                    'protocol': 'DoT' if server.use_tls else 'DNS',
                    'tls_host': server.tls_host if server.use_tls else None,
                    'stats': server.stats,
                    'raw_times': server.results
                }

        try:
            with open(json_filename, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"\n{Colors.GREEN}✓ JSON results saved to: {json_filename}{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.RED}Error saving JSON: {e}{Colors.ENDC}")

        # Save CSV
        csv_filename = f"dns_benchmark_{timestamp}.csv"
        try:
            with open(csv_filename, 'w', newline='') as csvfile:
                fieldnames = ['timestamp', 'server_name', 'server_ip', 'protocol',
                              'success_rate', 'avg_ms', 'min_ms', 'max_ms',
                              'median_ms', 'p95_ms', 'p99_ms', 'stdev_ms']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for server in self.servers:
                    if server.test_completed:
                        stats = server.stats
                        writer.writerow({
                            'timestamp': timestamp,
                            'server_name': server.name,
                            'server_ip': server.server,
                            'protocol': stats['protocol'],
                            'success_rate': round(stats['success_rate'], 1),
                            'avg_ms': round(stats['avg'], 1) if stats['avg'] < 9999 else 'Failed',
                            'min_ms': round(stats['min'], 1) if stats['min'] < 9999 else 'Failed',
                            'max_ms': round(stats['max'], 1) if stats['max'] < 9999 else 'Failed',
                            'median_ms': round(stats['median'], 1) if stats['median'] < 9999 else 'Failed',
                            'p95_ms': round(stats['p95'], 1) if stats['p95'] < 9999 else 'Failed',
                            'p99_ms': round(stats['p99'], 1) if stats['p99'] < 9999 else 'Failed',
                            'stdev_ms': round(stats['stdev'], 1) if stats['stdev'] > 0 else 0
                        })

            print(f"{Colors.GREEN}✓ CSV results saved to: {csv_filename}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}Error saving CSV: {e}{Colors.ENDC}")

def check_dependencies():
    """
    Check that required dependencies are installed
    """
    dependencies = {
        'dig': 'dnsutils or bind-utils',
        'kdig': 'knot-dnsutils'
    }

    missing = []
    for cmd, package in dependencies.items():
        try:
            result = subprocess.run(['which', cmd], capture_output=True)
            if result.returncode != 0:
                missing.append(f"{cmd} (install {package})")
        except:
            missing.append(f"{cmd} (install {package})")

    if missing:
        print(f"{Colors.RED}Missing dependencies:{Colors.ENDC}")
        for dep in missing:
            print(f"  - {dep}")
        print(f"\nInstall on Ubuntu/Debian: sudo apt-get install dnsutils knot-dnsutils")
        print(f"Install on Fedora/RHEL: sudo dnf install bind-utils knot-utils")
        print(f"Install on Arch: sudo pacman -S bind knot")
        print(f"Install on macOS: brew install knot")
        sys.exit(1)

def signal_handler(sig, frame):
    """
    Handle Ctrl+C gracefully
    """
    print(f"\n\n{Colors.YELLOW}Benchmark interrupted by user{Colors.ENDC}")
    sys.exit(0)

def main():
    """
    Main entry point
    """
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='DNS Performance Benchmark Tool - Test and compare DNS servers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Test google.com with 5 iterations
  %(prog)s example.com -i 10        # Test example.com with 10 iterations
  %(prog)s example.com -t 3         # Use 3 second timeout
  %(prog)s example.com --only-dot   # Test only DoT servers
  %(prog)s example.com --only-dns   # Test only traditional DNS
  %(prog)s -s Custom:192.168.1.1    # Add custom DNS server
  %(prog)s --parallel               # Run tests in parallel (faster)
        """
    )

    parser.add_argument('domain', nargs='?', default='google.com',
                        help='Domain to test (default: google.com)')
    parser.add_argument('-i', '--iterations', type=int, default=5,
                        help='Number of iterations per server (default: 5)')
    parser.add_argument('-t', '--timeout', type=int, default=5,
                        help='Query timeout in seconds (default: 5)')
    parser.add_argument('--only-dot', action='store_true',
                        help='Test only DoT servers')
    parser.add_argument('--only-dns', action='store_true',
                        help='Test only traditional DNS servers')
    parser.add_argument('-s', '--servers', nargs='+',
                        help='Add custom DNS servers (format: name:ip[:tls_host])')
    parser.add_argument('--parallel', action='store_true',
                        help='Run tests in parallel (experimental)')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {__version__}')

    args = parser.parse_args()

    # Check dependencies
    check_dependencies()

    # Create benchmark instance
    benchmark = DNSBenchmark(args.domain, args.iterations, args.timeout, args.parallel)

    # Add custom servers if specified
    if args.servers:
        for server_spec in args.servers:
            parts = server_spec.split(':')
            if len(parts) >= 2:
                name = parts[0]
                ip = parts[1]
                tls_host = parts[2] if len(parts) > 2 else None
                benchmark.servers.append(DNSServer(f"Custom-{name}", ip, tls_host))

    # Filter by protocol if specified
    if args.only_dot:
        benchmark.servers = [s for s in benchmark.servers if s.use_tls]
        print(f"{Colors.CYAN}Testing only DoT servers{Colors.ENDC}")
    elif args.only_dns:
        benchmark.servers = [s for s in benchmark.servers if not s.use_tls]
        print(f"{Colors.CYAN}Testing only traditional DNS servers{Colors.ENDC}")

    # Run benchmark
    benchmark.run_benchmark()

if __name__ == "__main__":
    main()