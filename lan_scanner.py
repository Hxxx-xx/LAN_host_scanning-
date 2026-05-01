#!/usr/bin/env python3
"""
局域网主机扫描工具
跨平台支持: Windows / Linux / macOS
功能: Ping主机发现 + 端口扫描 + OS指纹识别
无需管理员权限即可运行
"""

import argparse
import socket
import struct
import platform
import ipaddress
import asyncio
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional

# ============ 配置 ============
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

# 设备类型特征库
DEVICE_SIGNATURES = {
    "router": {
        "ports": [80, 443],
        "ports_alt": [8080, 8443, 53],
        "desc": "路由器/网关"
    },
    "printer": {
        "ports": [631, 9100],
        "ports_alt": [80, 443],
        "desc": "网络打印机"
    },
    "nas": {
        "ports": [445, 548],
        "ports_alt": [80, 443, 22],
        "desc": "NAS存储"
    },
    "camera": {
        "ports": [554, 80, 443],
        "ports_alt": [8080],
        "desc": "网络摄像头"
    },
    "tv": {
        "ports": [8001, 8002, 9000],
        "ports_alt": [80, 443],
        "desc": "智能电视"
    },
    "phone": {
        "ports": [62078, 5000, 7000],
        "ports_alt": [],
        "desc": "手机设备"
    },
    "computer": {
        "ports": [3389, 22, 5900, 445, 3306, 5432],
        "ports_alt": [80, 443],
        "desc": "电脑/服务器"
    },
    "iot": {
        "ports": [80, 8080],
        "ports_alt": [443],
        "desc": "智能家居设备"
    }
}

TIMEOUT = 0.5  # 端口扫描超时(秒)
PING_TIMEOUT = 1  # ping超时(秒)，macOS最小值为1
MAX_CONCURRENT = 100


@dataclass
class Host:
    """主机信息"""
    ip: str
    mac: str = "Unknown"
    hostname: str = "Unknown"
    status: str = "unknown"
    ports: List[int] = field(default_factory=list)
    os_guess: str = "Unknown"
    response_time: float = 0.0
    device_type: str = "Unknown"
    device_label: str = ""


# ============ 平台适配 ============
class Platform:
    """跨平台适配"""

    @staticmethod
    def get_system():
        return platform.system().lower()

    @staticmethod
    def get_local_ip() -> str:
        """获取本机IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    @staticmethod
    def get_subnet_mask() -> str:
        """获取子网掩码"""
        try:
            if Platform.get_system() == "windows":
                import subprocess
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if '255.255.255' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            return parts[1].strip()
            else:
                import subprocess
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                # 解析en0接口的掩码
                current_iface = None
                for line in result.stdout.split('\n'):
                    # 检测接口名行（如 "en0:"）
                    if line.strip().endswith(':') and not line.strip().startswith(' '):
                        current_iface = line.strip().rstrip(':')
                    elif 'netmask' in line and current_iface and current_iface.startswith('en'):
                        parts = line.split('netmask')
                        if len(parts) > 1:
                            mask = parts[1].strip().split()[0]
                            if mask.startswith('0x'):
                                ip_int = int(mask, 16)
                                return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
                            return mask
        except:
            pass
        return "255.255.255.0"  # 默认

    @staticmethod
    def get_gateway() -> str:
        """获取网关"""
        try:
            if Platform.get_system() == "windows":
                import subprocess
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Default Gateway' in line or '默认网关' in line:
                        parts = line.split(':')
                        if len(parts) > 1 and parts[1].strip():
                            return parts[1].strip()
            else:
                import subprocess
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        if 'via' in parts:
                            idx = parts.index('via')
                            return parts[idx + 1]
        except:
            pass
        return "192.168.1.1"  # 默认


# ============ 网络工具 ============
class NetworkUtils:
    """网络工具类"""

    @staticmethod
    def ip_to_int(ip: str) -> int:
        return int(ipaddress.ip_address(ip))

    @staticmethod
    def int_to_ip(num: int) -> str:
        return str(ipaddress.ip_address(num))

    @staticmethod
    def get_network_range(ip: str, mask: str) -> tuple:
        """计算网络范围"""
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(network.network_address), str(network.broadcast_address)

    @staticmethod
    def cidr_to_mask(cidr: int) -> str:
        """CIDR转子网掩码"""
        return str(ipaddress.IPv4Network(f"0.0.0.0/{cidr}", strict=False).netmask)

    @staticmethod
    def resolve_hostname(ip: str) -> str:
        """反向解析主机名"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return "Unknown"

    @staticmethod
    def get_mac_address(ip: str) -> str:
        """从路由表/ARP缓存获取MAC地址"""
        try:
            import subprocess
            system = Platform.get_system()
            if system == "windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if '-' in part and len(part) == 17:
                                return part.upper()
            elif system == "darwin":  # macOS - 使用netstat获取
                result = subprocess.run(['netstat', '-arn'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ip in line and 'UHL' in line:
                        parts = line.split()
                        # 格式: 192.168.1.1  a8:3b:5c:18:f9:c0  UHLWIir  en0  1160
                        for i, p in enumerate(parts):
                            if p == ip and i + 1 < len(parts):
                                mac = parts[i + 1]
                                if ':' in mac and len(mac) == 17:
                                    return mac.upper()
            else:  # Linux
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if '-' in part and len(part) == 17:
                                return part.upper()
                            if ':' in part and len(part) == 17:
                                return part.upper()
        except:
            pass
        return "Unknown"

    @staticmethod
    def guess_os(ttl: int) -> str:
        """根据TTL猜测操作系统"""
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Network Device/Unix"
        return "Unknown"

    @staticmethod
    def identify_device(ip: str, ports: List[int], gateway: str) -> tuple:
        """根据端口特征识别设备类型"""
        if ip == gateway:
            return "router", "🌐 网关/路由器"

        if not ports:
            return "unknown", "❓ 未知设备"

        open_set = set(ports)

        # 计分系统 - 匹配端口越多得分越高
        scores = {}
        for dev_type, sig in DEVICE_SIGNATURES.items():
            score = 0
            required = sig["ports"]
            optional = sig["ports_alt"]

            # 必需端口匹配 (每个+10分)
            matched_required = sum(1 for p in required if p in open_set)
            score += matched_required * 10

            # 可选端口匹配 (每个+5分)
            matched_optional = sum(1 for p in optional if p in open_set)
            score += matched_optional * 5

            if score > 0:
                scores[dev_type] = score

        if not scores:
            return "unknown", "❓ 未知设备"

        # 取最高分
        best_type = max(scores, key=scores.get)

        labels = {
            "router": "🌐 网关/路由器",
            "printer": "🖨️ 网络打印机",
            "nas": "💾 NAS存储",
            "camera": "📷 网络摄像头",
            "tv": "📺 智能电视",
            "phone": "📱 手机设备",
            "computer": "💻 电脑/服务器",
            "iot": "🏠 智能家居设备"
        }

        return best_type, labels.get(best_type, "❓ 未知设备")

    @staticmethod
    def ping_host(ip: str, timeout: float = PING_TIMEOUT) -> tuple:
        """Ping检测主机存活"""
        import time
        start = time.time()

        try:
            system = Platform.get_system()
            if system == "windows":
                import subprocess
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip],
                    capture_output=True, text=True, timeout=timeout + 1
                )
                alive = result.returncode == 0
            elif system == "darwin":  # macOS
                import subprocess
                timeout_sec = max(1, int(timeout))
                result = subprocess.run(
                    ['ping', '-c', '1', '-t', str(timeout_sec), ip],
                    capture_output=True, text=True, timeout=timeout + 1
                )
                alive = result.returncode == 0
            else:  # Linux
                import subprocess
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', str(int(timeout)), ip],
                    capture_output=True, text=True, timeout=timeout + 1
                )
                alive = result.returncode == 0

            # 提取TTL
            ttl = 64  # 默认
            if alive:
                output = result.stdout.lower()
                if 'ttl=' in output or 'time=' in output:
                    for part in output.split():
                        if part.startswith('ttl='):
                            try:
                                ttl = int(part.split('=')[1].split()[0])
                            except:
                                pass
                        elif part.startswith('time='):
                            try:
                                rtt = float(part.split('=')[1])
                            except:
                                pass

            elapsed = time.time() - start
            return alive, ttl, elapsed

        except Exception as e:
            return False, 0, time.time() - start


# ============ ARP扫描 ============
class ARPScanner:
    """ARP扫描器"""

    def __init__(self, subnet: str):
        self.subnet = subnet
        self.hosts: List[Host] = []

    def scan(self, progress_callback=None) -> List[Host]:
        """执行ARP扫描"""
        import sys
        print(f"[*] 开始ARP扫描: {self.subnet}", flush=True)

        # 解析网段
        try:
            network = ipaddress.IPv4Network(self.subnet, strict=False)
            ip_list = list(network.hosts())
        except Exception as e:
            print(f"[!] 网段解析失败: {e}")
            return []

        total = len(ip_list)
        print(f"[*] 待扫描主机数: {total}", flush=True)

        for i, ip in enumerate(ip_list):
            ip_str = str(ip)
            alive, ttl, elapsed = NetworkUtils.ping_host(ip_str)

            if alive:
                mac = NetworkUtils.get_mac_address(ip_str)
                host = Host(
                    ip=ip_str,
                    mac=mac,
                    status="up",
                    os_guess=NetworkUtils.guess_os(ttl),
                    response_time=round(elapsed * 1000, 2)
                )
                self.hosts.append(host)
                print(f"[+] 发现主机: {ip_str} (TTL:{ttl}, RTT:{elapsed*1000:.1f}ms, MAC:{mac})", flush=True)

            if progress_callback:
                progress_callback(i + 1, total)

        print(f"[*] ARP扫描完成, 发现 {len(self.hosts)} 台存活主机", flush=True)
        return self.hosts


# ============ 端口扫描 ============
class PortScanner:
    """端口扫描器"""

    def __init__(self, hosts: List[Host], ports: List[int] = None, gateway: str = ""):
        self.hosts = hosts
        self.ports = ports or COMMON_PORTS
        self.gateway = gateway

    @staticmethod
    def check_port(ip: str, port: int, timeout: float = TIMEOUT) -> Optional[int]:
        """检查单个端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None

    def scan(self, progress_callback=None) -> List[Host]:
        """执行端口扫描"""
        print(f"[*] 开始端口扫描...", flush=True)

        from concurrent.futures import ThreadPoolExecutor

        total_hosts = len(self.hosts)

        for host_idx, host in enumerate(self.hosts):
            print(f"    扫描 {host.ip}...", end="", flush=True)

            # 使用线程池并发扫描，每个任务绑定固定IP
            def scan_ports(ip):
                return [p for p in self.ports if self.check_port(ip, p) is not None]

            with ThreadPoolExecutor(max_workers=10) as executor:
                future = executor.submit(scan_ports, host.ip)
                open_ports = future.result(timeout=10)

            host.ports = sorted(open_ports)

            # 识别设备类型
            host.device_type, host.device_label = NetworkUtils.identify_device(
                host.ip, open_ports, self.gateway
            )

            if open_ports:
                port_info = ", ".join([f"{p}({PORT_SERVICES.get(p, '?')})" for p in open_ports[:5]])
                if len(open_ports) > 5:
                    port_info += f" ... (+{len(open_ports) - 5})"
                print(f" {port_info} [{host.device_label}]", flush=True)
            else:
                print(f" 无开放端口 [{host.device_label}]", flush=True)

            if progress_callback:
                progress_callback(host_idx + 1, total_hosts)

        print(f"[*] 端口扫描完成", flush=True)
        return self.hosts


# ============ 主机名解析 ============
class HostResolver:
    """主机名解析"""

    def __init__(self, hosts: List[Host]):
        self.hosts = hosts

    def resolve(self) -> List[Host]:
        """解析主机名"""
        print(f"[*] 解析主机名...")

        for host in self.hosts:
            try:
                host.hostname = NetworkUtils.resolve_hostname(host.ip)
            except:
                pass

        return self.hosts


# ============ 输出格式化 ============
class OutputFormatter:
    """输出格式化"""

    @staticmethod
    def print_summary(hosts: List[Host]):
        """打印汇总信息"""
        print("\n" + "=" * 70)
        print(" " * 20 + "局 域 网 主 机 扫 描 报 告")
        print("=" * 70)
        print(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"发现主机: {len(hosts)} 台")
        print("-" * 70)

        for host in hosts:
            label = host.device_label if host.device_label else ""
            print(f"\n[{host.status.upper()}] {host.ip} {label}")
            print(f"    主机名: {host.hostname}")
            print(f"    MAC地址: {host.mac}")
            print(f"    设备类型: {host.device_type}")
            print(f"    OS猜测: {host.os_guess}")
            print(f"    响应时间: {host.response_time:.2f} ms")

            if host.ports:
                print(f"    开放端口:")
                for port in host.ports:
                    service = PORT_SERVICES.get(port, "?")
                    print(f"        {port}/tcp  {service}")
            else:
                print(f"    开放端口: 无")

        print("\n" + "=" * 70)

    @staticmethod
    def export_json(hosts: List[Host], filename: str):
        """导出JSON"""
        data = [asdict(host) for host in hosts]
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[*] 结果已保存: {filename}")

    @staticmethod
    def export_csv(hosts: List[Host], filename: str):
        """导出CSV"""
        import csv
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', '主机名', 'MAC', '状态', 'OS', '响应时间(ms)', '开放端口'])
            for host in hosts:
                writer.writerow([
                    host.ip,
                    host.hostname,
                    host.mac,
                    host.status,
                    host.os_guess,
                    host.response_time,
                    ','.join(map(str, host.ports)) or 'None'
                ])
        print(f"[*] 结果已保存: {filename}")


# ============ 主程序 ============
def parse_arguments():
    parser = argparse.ArgumentParser(
        description='局域网主机扫描工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  python lan_scanner.py                      # 扫描当前网段
  python lan_scanner.py --ip 192.168.1.1    # 指定IP
  python lan_scanner.py -o result.json       # 输出JSON
  python lan_scanner.py --no-portscan        # 仅主机发现
        '''
    )
    parser.add_argument('-i', '--ip', help='指定IP或网段 (如 192.168.1.0/24)')
    parser.add_argument('-o', '--output', help='输出文件 (JSON/CSV)')
    parser.add_argument('--no-portscan', action='store_true', help='跳过端口扫描')
    parser.add_argument('-p', '--ports', help='指定端口 (逗号分隔)')
    parser.add_argument('-t', '--threads', type=int, default=MAX_CONCURRENT, help=f'并发数 (默认 {MAX_CONCURRENT})')
    return parser.parse_args()


def main():
    args = parse_arguments()

    print("\n" + "=" * 50)
    print("  局域网主机扫描工具 v1.0")
    print("=" * 50)

    # 获取本地网络信息
    local_ip = Platform.get_local_ip()
    subnet_mask = Platform.get_subnet_mask()
    gateway = Platform.get_gateway()

    print(f"\n[*] 本机IP: {local_ip}")
    print(f"[*] 子网掩码: {subnet_mask}")
    print(f"[*] 网关: {gateway}")

    # 确定扫描目标
    if args.ip:
        target = args.ip
    else:
        # 自动计算网段
        target = f"{gateway.rsplit('.', 1)[0]}.0/24"

    print(f"[*] 扫描目标: {target}\n")

    # 解析端口列表
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("[!] 端口格式错误")
            return

    # 执行扫描
    arp_scanner = ARPScanner(target)
    hosts = arp_scanner.scan()

    if not hosts:
        print("[*] 未发现存活主机")
        return

    # 端口扫描
    if not args.no_portscan:
        port_scanner = PortScanner(hosts, ports, gateway)
        hosts = port_scanner.scan()

    # 主机名解析
    resolver = HostResolver(hosts)
    hosts = resolver.resolve()

    # 输出结果
    OutputFormatter.print_summary(hosts)

    # 保存文件
    if args.output:
        if args.output.endswith('.json'):
            OutputFormatter.export_json(hosts, args.output)
        elif args.output.endswith('.csv'):
            OutputFormatter.export_csv(hosts, args.output)
        else:
            OutputFormatter.export_json(hosts, args.output + '.json')


if __name__ == '__main__':
    main()
