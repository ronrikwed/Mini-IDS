#!/usr/bin/env python3


# 실행
# venv\Scripts\activate  # 가상환경 활성화
# cd (파이썬 파일이 위치하는 디렉토리)
# python mini_ids.py
# python mini_ids.py -i "이더넷"


import argparse
import time
from collections import defaultdict, deque

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list
except ImportError:
    raise SystemExit


class PortScanDetector:
    def __init__(self, window_seconds: int = 5, port_threshold: int = 10):
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold
        self._history: dict[str, deque] = defaultdict(deque)
        self._last_alert: dict[str, float] = {}
        self._alert_cooldown = 10

    def _prune_old(self, src_ip: str, now: float) -> None:
        dq = self._history[src_ip]
        while dq and now - dq[0][0] > self.window_seconds:
            dq.popleft()

    def feed(self, src_ip: str, dst_port: int, now: float | None = None):
        now = now if now is not None else time.time()
        dq = self._history[src_ip]
        dq.append((now, dst_port))
        self._prune_old(src_ip, now)

        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) >= self.port_threshold:
            last = self._last_alert.get(src_ip, 0)
            if now - last >= self._alert_cooldown:
                self._last_alert[src_ip] = now
                return {
                    "type": "PORT_SCAN",
                    "src_ip": src_ip,
                    "distinct_ports": len(distinct_ports),
                    "ports": sorted(distinct_ports),
                    "window_seconds": self.window_seconds,
                }
        return None


class Rule:
    def __init__(
        self,
        name: str,
        proto: str | None = None,
        dst_port: int | None = None,
        src_port: int | None = None,
        tcp_flags: str | None = None,
        payload_contains: bytes | None = None,
    ):
        self.name = name
        self.proto = proto
        self.dst_port = dst_port
        self.src_port = src_port
        self.tcp_flags = tcp_flags
        self.payload_contains = payload_contains

    def matches(self, pkt) -> bool:
        if IP not in pkt:
            return False

        if self.proto == "tcp" and TCP not in pkt:
            return False
        if self.proto == "udp" and UDP not in pkt:
            return False

        layer = pkt[TCP] if TCP in pkt else (pkt[UDP] if UDP in pkt else None)
        if layer is None and (self.dst_port or self.src_port or self.tcp_flags):
            return False

        if self.dst_port is not None and layer.dport != self.dst_port:
            return False
        if self.src_port is not None and layer.sport != self.src_port:
            return False
        if self.tcp_flags is not None:
            if TCP not in pkt or str(pkt[TCP].flags) != self.tcp_flags:
                return False
        if self.payload_contains is not None:
            if Raw not in pkt or self.payload_contains not in bytes(pkt[Raw].load):
                return False

        return True


class SignatureDetector:
    def __init__(self, rules: list[Rule] | None = None):
        self.rules: list[Rule] = rules or []

    def add_rule(self, rule: Rule):
        self.rules.append(rule)

    def feed(self, pkt) -> list[dict]:
        alerts = []
        for rule in self.rules:
            if rule.matches(pkt):
                alerts.append({
                    "type": "SIGNATURE_MATCH",
                    "rule": rule.name,
                    "src_ip": pkt[IP].src if IP in pkt else None,
                    "dst_ip": pkt[IP].dst if IP in pkt else None,
                })
        return alerts


class MiniIDS:
    def __init__(self, port_scan: PortScanDetector, sig_detector: SignatureDetector):
        self.port_scan = port_scan
        self.sig_detector = sig_detector

    def _log_alert(self, alert: dict):
        ts = time.strftime("%H:%M:%S")
        if alert["type"] == "PORT_SCAN":
            print(
                f"[{ts}] [PORT SCAN] {alert['src_ip']} 가 {alert['window_seconds']}초 동안 "
                f"서로 다른 포트 {alert['distinct_ports']}개에 접근함 -> {alert['ports'][:15]}"
                + (" ..." if len(alert['ports']) > 15 else "")
            )
        elif alert["type"] == "SIGNATURE_MATCH":
            print(
                f"[{ts}] [SIGNATURE] '{alert['rule']}' 매칭: "
                f"{alert['src_ip']} -> {alert['dst_ip']}"
            )

    def handle_packet(self, pkt):
        if IP not in pkt:
            return

        src_ip = pkt[IP].src

        dport = None
        if TCP in pkt:
            dport = pkt[TCP].dport
        elif UDP in pkt:
            dport = pkt[UDP].dport

        if dport is not None:
            alert = self.port_scan.feed(src_ip, dport)
            if alert:
                self._log_alert(alert)

        for alert in self.sig_detector.feed(pkt):
            self._log_alert(alert)


def default_rules() -> list[Rule]:
    return [
        Rule(name="Telnet(23) 접근 시도", proto="tcp", dst_port=23),
        Rule(name="FTP(21) 접근 시도", proto="tcp", dst_port=21),
        Rule(name="SYN-only 패킷(스캔/연결 시도)", proto="tcp", tcp_flags="S"),
        Rule(name="평문 password 필드 노출", payload_contains=b"password="),
    ]


def run_demo():
    ids = MiniIDS(
        port_scan=PortScanDetector(window_seconds=5, port_threshold=5),
        sig_detector=SignatureDetector(default_rules()),
    )

    print("=== 데모: 포트 스캔 시뮬레이션 (127.0.0.1 -> 1.2.3.4, 포트 5개 연속 접근) ===")
    for port in [22, 23, 80, 443, 8080]:
        pkt = IP(src="127.0.0.1", dst="1.2.3.4") / TCP(dport=port, flags="S")
        ids.handle_packet(pkt)

    print("\n=== 데모: 시그니처 매칭 (Telnet 접근 + 평문 비밀번호) ===")
    pkt1 = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=23, flags="S")
    ids.handle_packet(pkt1)

    pkt2 = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80) / Raw(load=b"username=admin&password=1234")
    ids.handle_packet(pkt2)


def main():
    parser = argparse.ArgumentParser(description="Mini IDS - Port Scan / 특정 패킷 탐지")
    parser.add_argument("-i", "--interface", help="스니핑할 네트워크 인터페이스 (예: eth0)")
    parser.add_argument("--window", type=int, default=5, help="포트 스캔 탐지 윈도우(초)")
    parser.add_argument("--threshold", type=int, default=10, help="포트 스캔 판정 임계 포트 수")
    parser.add_argument("--demo", action="store_true", help="실제 스니핑 없이 데모만 실행")
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    ids = MiniIDS(
        port_scan=PortScanDetector(window_seconds=args.window, port_threshold=args.threshold),
        sig_detector=SignatureDetector(default_rules()),
    )

    print(f"[*] Mini IDS 시작 (interface={args.interface or 'auto'}, "
          f"window={args.window}s, threshold={args.threshold} ports)")
    print(f"[*] 사용 가능한 인터페이스: {get_if_list()}")
    print("[*] Ctrl+C 로 종료")

    try:
        sniff(iface=args.interface, prn=ids.handle_packet, store=False)
    except PermissionError:
        print("권한 오류: 관리자 권한으로 실행해야 패킷 캡처가 가능합니다.")
    except KeyboardInterrupt:
        print("\n[*] 종료합니다.")


if __name__ == "__main__":
    main()
