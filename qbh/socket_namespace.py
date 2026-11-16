"""Linux privileged network boundary for direct socket assessment workers.

The network namespace is owned by the host user namespace. Scanner processes
enter a separate unprivileged user namespace and cannot alter its firewall.
HTTP path/method policies require HTTP mediation, not just this L3/L4 boundary.
"""

from __future__ import annotations

import ipaddress
import secrets
import subprocess

from .authorization import RuleForbidden
from .network_policy import validate_ip


class SocketNamespace:
    def __init__(self, authorization, destinations, *, ports):
        authorization.ensure_active()
        if authorization.dry_run:
            raise RuleForbidden("dry_run_process_forbidden")
        if authorization.request_restrictions:
            raise RuleForbidden("raw_socket_path_policy_requires_application_gateway")
        self.auth = authorization
        self.destinations = tuple(str(ipaddress.ip_address(ip)) for ip in destinations)
        if not self.destinations or len(self.destinations) > 256:
            raise RuleForbidden("invalid_socket_destination_count")
        # Inputs must already be scope-authorized identities, not arbitrary DNS
        # answers. Callers cannot use public-address status as a scope grant.
        for ip in self.destinations:
            authorization.authorize_host(ip)
            validate_ip(authorization, ip)
        self.ports = tuple(sorted(set(ports)))
        if not self.ports or any(
            type(p) is not int or not 1 <= p <= 65535 for p in self.ports
        ):
            raise RuleForbidden("invalid_socket_ports")
        if len(self.ports) * len(self.destinations) > 1024:
            raise RuleForbidden('socket_firewall_rule_budget_exceeded')
        suffix = secrets.token_hex(4)
        self.name = "xez-" + suffix
        self.host_if, self.child_if = "xh" + suffix, "xc" + suffix
        number = secrets.randbelow(16384)
        network = ipaddress.ip_network(f"198.19.{number // 64}.{(number % 64) * 4}/30")
        self.gateway, self.address = str(network[1]), str(network[2])
        self.created = self.linked = False
        self.host_rules = []

    @staticmethod
    def command(*args):
        return subprocess.run(
            ["sudo", "-n", *args], check=True, capture_output=True, timeout=15
        )

    def inside(self, *args):
        return self.command("ip", "netns", "exec", self.name, *args)

    def host_rule(self, table, chain, *rule):
        self.command("iptables", "-w", "-t", table, "-I", chain, "1", *rule)
        self.host_rules.append((table, chain, rule))

    def validate(self):
        self.auth.ensure_active()
        if self.auth.dry_run or self.auth.request_restrictions:
            raise RuleForbidden("raw_socket_policy_changed")
        for ip in self.destinations:
            self.auth.authorize_host(ip)
            validate_ip(self.auth, ip)

    def __enter__(self):
        self.validate()
        try:
            self.command("ip", "netns", "add", self.name)
            self.created = True
            self.command(
                "ip",
                "link",
                "add",
                self.host_if,
                "type",
                "veth",
                "peer",
                "name",
                self.child_if,
            )
            self.linked = True
            self.command("ip", "link", "set", self.child_if, "netns", self.name)
            self.command("ip", "addr", "add", self.gateway + "/30", "dev", self.host_if)
            self.command("ip", "link", "set", self.host_if, "up")
            self.inside("ip", "addr", "add", self.address + "/30", "dev", self.child_if)
            self.inside("ip", "link", "set", self.child_if, "up")
            self.inside("ip", "link", "set", "lo", "up")
            # Default deny precedes any scanner process. IPv6 has no egress
            # route here and an explicit firewall deny as an independent gate.
            for family in ("iptables", "ip6tables"):
                self.inside(family, "-P", "OUTPUT", "DROP")
                self.inside(family, "-P", "FORWARD", "DROP")
                self.inside(family, "-P", "INPUT", "DROP")
                self.inside(
                    family,
                    "-A",
                    "INPUT",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                )
            for ip in self.destinations:
                if ":" in ip:
                    raise RuleForbidden("ipv6_socket_gateway_not_configured")
                self.inside("ip", "route", "replace", ip + "/32", "via", self.gateway)
                for port in self.ports:
                    for protocol in ("tcp", "udp"):
                        self.inside(
                            "iptables",
                            "-A",
                            "OUTPUT",
                            "-d",
                            ip,
                            "-p",
                            protocol,
                            "--dport",
                            str(port),
                            "-j",
                            "ACCEPT",
                        )
            self.inside(
                "iptables",
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-j",
                "REJECT",
                "--reject-with",
                "tcp-reset",
            )
            # Source check prevents packets with forged source addresses entering
            # host routing. Rules match only this task's unique veth interface.
            self.host_rule("filter", "FORWARD", "-i", self.host_if, "-j", "DROP")
            self.host_rule(
                "filter",
                "FORWARD",
                "-i",
                self.host_if,
                "-s",
                self.address,
                "-j",
                "ACCEPT",
            )
            self.host_rule(
                "filter",
                "FORWARD",
                "-o",
                self.host_if,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            )
            self.host_rule("nat", "POSTROUTING", "-s", self.address, "-j", "MASQUERADE")
            return self
        except BaseException:
            self.close()
            raise

    def wrap(self, command):
        self.validate()
        # Host root privileges end at bubblewrap; the executable runs without
        # capabilities in a new user/PID/filesystem namespace. No host proc/home.
        return [
            "sudo",
            "-n",
            "ip",
            "netns",
            "exec",
            self.name,
            "bwrap",
            "--unshare-all",
            "--share-net",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--cap-drop",
            "ALL",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/etc",
            "--ro-bind",
            "/etc/alternatives",
            "/etc/alternatives",
            "--ro-bind",
            "/etc/ld.so.cache",
            "/etc/ld.so.cache",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/tmp",
            "--chdir",
            "/tmp",
            *command,
        ]

    def close(self):
        errors = []
        for table, chain, rule in reversed(self.host_rules):
            try:
                self.command("iptables", "-w", "-t", table, "-D", chain, *rule)
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(exc)
        self.host_rules.clear()
        if self.linked:
            try:
                self.command("ip", "link", "del", self.host_if)
                self.linked = False
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(exc)
        if self.created:
            try:
                self.command("ip", "netns", "del", self.name)
                self.created = False
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(exc)
        if errors:
            raise RuntimeError(
                "socket_namespace_cleanup_failed; inspect task interface and rules"
            ) from errors[0]

    def __exit__(self, *exc):
        self.close()
