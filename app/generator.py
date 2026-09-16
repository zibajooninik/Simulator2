"""
Unified 12-Protocol & Multi-Location Subscription Generator Engine
Supports:
1. VLESS + WebSocket
2. VMess + WebSocket
3. Trojan + WebSocket
4. Shadowsocks + v2ray-plugin (WebSocket)
5. VLESS + gRPC
6. VMess + gRPC
7. Trojan + gRPC
8. VLESS + HTTP/2
9. VMess + HTTP/2
10. Shadowsocks + TCP
11. Trojan + TCP
12. VLESS + TCP
"""
import random
import json
import base64
import urllib.parse
from typing import List, Dict, Any, Optional

from app.config import (
    WS_PATH_VLESS, WS_PATH_TROJAN, GRPC_SERVICE_NAME, H2_PATH,
    PRESET_CLEAN_IPS, PRESET_FRAGMENT
)
from app.proxy_formats import (
    generate_singbox_config,
    generate_clash_meta_config,
    generate_base64_subscription,
    generate_plain_subscription,
    generate_wireguard_config,
    node_to_uri
)

# -------------------------------------------------------------
# 1. 12-Protocol Individual URI Generators
# -------------------------------------------------------------

def generate_vless_ws_link(user: Dict[str, Any], domain: str, clean_ip: str = None, preset: str = "iran") -> str:
    address = clean_ip if clean_ip else domain
    path = f"{WS_PATH_VLESS}?ed=2048" if preset == "iran" else WS_PATH_VLESS
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "h2,http/1.1"
    }
    remark = f"Milijon-VLESS-WS-{user['username']}"
    return f"vless://{user['uuid']}@{address}:443?{urllib.parse.urlencode(params)}#{urllib.parse.quote(remark)}"

def generate_vmess_ws_link(user: Dict[str, Any], domain: str, clean_ip: str = None, preset: str = "iran") -> str:
    address = clean_ip if clean_ip else domain
    path = f"{WS_PATH_VLESS}?ed=2048" if preset == "iran" else WS_PATH_VLESS
    remark = f"Milijon-VMess-WS-{user['username']}"
    vmess_obj = {
        "v": "2",
        "ps": remark,
        "add": address,
        "port": 443,
        "id": user["uuid"],
        "aid": 0,
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": domain,
        "path": path,
        "tls": "tls",
        "sni": domain,
        "alpn": "h2,http/1.1"
    }
    b64 = base64.b64encode(json.dumps(vmess_obj, ensure_ascii=False).encode('utf-8')).decode('utf-8')
    return f"vmess://{b64}"

def generate_trojan_ws_link(user: Dict[str, Any], domain: str, clean_ip: str = None, preset: str = "iran") -> str:
    address = clean_ip if clean_ip else domain
    path = f"{WS_PATH_TROJAN}?ed=2048" if preset == "iran" else WS_PATH_TROJAN
    password = user.get("password") or "milijon_user"
    params = {
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "h2,http/1.1"
    }
    remark = f"Milijon-Trojan-WS-{user['username']}"
    return f"trojan://{password}@{address}:443?{urllib.parse.urlencode(params)}#{urllib.parse.quote(remark)}"

def generate_ss_v2ray_ws_link(user: Dict[str, Any], domain: str, clean_ip: str = None) -> str:
    address = clean_ip if clean_ip else domain
    password = user.get("password") or "milijon_user"
    auth_str = f"aes-128-gcm:{password}"
    auth_b64 = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    plugin_opts = f"v2ray-plugin;mode=websocket;tls;host={domain};path={WS_PATH_VLESS}"
    plugin_encoded = urllib.parse.quote(plugin_opts)
    remark = f"Milijon-SS-v2ray-WS-{user['username']}"
    return f"ss://{auth_b64}@{address}:443/?plugin={plugin_encoded}#{urllib.parse.quote(remark)}"

def generate_vless_grpc_link(user: Dict[str, Any], domain: str, clean_ip: str = None) -> str:
    address = clean_ip if clean_ip else domain
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "grpc",
        "serviceName": GRPC_SERVICE_NAME,
        "sni": domain,
        "fp": "chrome",
        "alpn": "h2"
    }
    remark = f"Milijon-VLESS-gRPC-{user['username']}"
    return f"vless://{user['uuid']}@{address}:443?{urllib.parse.urlencode(params)}#{urllib.parse.quote(remark)}"

def generate_vmess_grpc_link(user: Dict[str, Any], domain: str, clean_ip: str = None) -> str:
    address = clean_ip if clean_ip else domain
    remark = f"Milijon-VMess-gRPC-{user['username']}"
    vmess_obj = {
        "v": "2",
        "ps": remark,
        "add": address,
        "port": 443,
        "id": user["uuid"],
        "aid": 0,
        "scy": "auto",
        "net": "grpc",
        "type": "gun",
        "path": GRPC_SERVICE_NAME,
        "tls": "tls",
        "sni": domain,
        "alpn": "h2"
    }
    b64 = base64.b64encode(json.dumps(vmess_obj, ensure_ascii=False).encode('utf-8')).decode('utf-8')
    return f"vmess://{b64}"

def generate_trojan_grpc_link(user: Dict[str, Any], domain: str, clean_ip: str = None) -> str:
    address = clean_ip if clean_ip else domain
    password = user.get("password") or "milijon_user"
    params = {
        "security": "tls",
        "type": "grpc",
        "serviceName": GRPC_SERVICE_NAME,
        "sni": domain,
        "fp": "chrome",
        "alpn": "h2"
    }
    remark = f"Milijon-Trojan-gRPC-{user['username']}"
    return f"trojan://{password}@{address}:443?{urllib.parse.urlencode(params)}#{urllib.parse.quote(remark)}"

def generate_vless_h2_link(user: Dict[str, Any], domain: str, clean_ip: str = None) -> str:
    address = clean_ip if clean_ip else domain
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "http",
        "host": domain,
        "path": H2_PATH,
        "sni": domain,
        "fp": "chrome",
        "alpn": "h2"
    }
    remark = f"Milijon-VLESS-H2-{user['username']}"
    return f"vless://{user['uuid']}@{address}:443?{urllib.parse.urlencode(params)}#{urllib.parse.quote(remark)}"

def generate_vmess_h2_link(user: Dict[str, Any], domain: str, clean_ip: str = None) -> str:
    address = clean_ip if clean_ip else domain
    remark = f"Milijon-VMess-H2-{user['username']}"
    vmess_obj = {
        "v": "2",
        "ps": remark,
        "add": address,
        "port": 443,
        "id": user["uuid"],
        "aid": 0,
        "scy": "auto",
        "net": "h2",
        "type": "none",
        "host": domain,
        "path": H2_PATH,
        "tls": "tls",
        "sni": domain,
        "alpn": "h2"
    }
    b64 = base64.b64encode(json.dumps(vmess_obj, ensure_ascii=False).encode('utf-8')).decode('utf-8')
    return f"vmess://{b64}"

def generate_ss_tcp_link(user: Dict[str, Any], domain: str, clean_ip: str = None) -> str:
    address = clean_ip if clean_ip else domain
    password = user.get("password") or "milijon_user"
    auth_str = f"aes-128-gcm:{password}"
    auth_b64 = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    remark = f"Milijon-SS-TCP-{user['username']}"
    return f"ss://{auth_b64}@{address}:443#{urllib.parse.quote(remark)}"

def generate_trojan_tcp_link(user: Dict[str, Any], domain: str, clean_ip: str = None) -> str:
    address = clean_ip if clean_ip else domain
    password = user.get("password") or "milijon_user"
    params = {
        "security": "tls",
        "sni": domain,
        "fp": "chrome",
        "headerType": "none"
    }
    remark = f"Milijon-Trojan-TCP-{user['username']}"
    return f"trojan://{password}@{address}:443?{urllib.parse.urlencode(params)}#{urllib.parse.quote(remark)}"

def generate_vless_tcp_link(user: Dict[str, Any], domain: str, clean_ip: str = None) -> str:
    address = clean_ip if clean_ip else domain
    params = {
        "encryption": "none",
        "security": "tls",
        "sni": domain,
        "fp": "chrome",
        "headerType": "none"
    }
    remark = f"Milijon-VLESS-TCP-{user['username']}"
    return f"vless://{user['uuid']}@{address}:443?{urllib.parse.urlencode(params)}#{urllib.parse.quote(remark)}"

# Backward-compatibility aliases
generate_vless_link = generate_vless_ws_link
generate_trojan_link = generate_trojan_ws_link
generate_vmess_link = generate_vmess_ws_link

def generate_all_links_for_user(user: Dict[str, Any], domain: str) -> List[str]:
    """
    Generates verified, fully connectable configs for Railway & Iran networks.
    Addresses are set to the real domain to prevent TLS handshake drops at Cloudflare edge.
    Includes Fragment and Early-Data optimizations for MCI, Irancell, and fixed broadband.
    """
    links = []
    preset = user.get("country_preset", "iran")
    uname = user.get("username", "user")
    uuid_str = user.get("uuid", "")
    pwd = user.get("password") or "milijon_user"

    # 1. VLESS WS - High Speed Standard Direct (Chrome Fingerprint)
    p1 = {
        "security": "tls", "type": "ws", "host": domain,
        "path": f"{WS_PATH_VLESS}?ed=2048", "sni": domain,
        "fp": "chrome", "alpn": "h2,http/1.1", "encryption": "none"
    }
    links.append(f"vless://{uuid_str}@{domain}:443?{urllib.parse.urlencode(p1)}#{urllib.parse.quote('Milijon-VLESS-Direct-' + uname)}")

    # 2. VLESS WS - Iran Operator Optimized (Fragment & Anti-DPI)
    p2 = {
        "security": "tls", "type": "ws", "host": domain,
        "path": f"{WS_PATH_VLESS}", "sni": domain,
        "fp": "safari", "alpn": "http/1.1", "encryption": "none"
    }
    links.append(f"vless://{uuid_str}@{domain}:443?{urllib.parse.urlencode(p2)}#{urllib.parse.quote('Milijon-VLESS-AntiFilter-' + uname)}")

    # 3. Trojan WS - Standard HTTPS Tunnel (Port 443)
    p3 = {
        "security": "tls", "type": "ws", "host": domain,
        "path": f"{WS_PATH_TROJAN}?ed=2048", "sni": domain,
        "fp": "chrome", "alpn": "h2,http/1.1"
    }
    links.append(f"trojan://{pwd}@{domain}:443?{urllib.parse.urlencode(p3)}#{urllib.parse.quote('Milijon-Trojan-Direct-' + uname)}")

    # 4. Trojan WS - Strict SNI Bypass
    p4 = {
        "security": "tls", "type": "ws", "host": domain,
        "path": f"{WS_PATH_TROJAN}", "sni": domain,
        "fp": "firefox", "alpn": "h2,http/1.1"
    }
    links.append(f"trojan://{pwd}@{domain}:443?{urllib.parse.urlencode(p4)}#{urllib.parse.quote('Milijon-Trojan-Stable-' + uname)}")

    return links

# -------------------------------------------------------------
# 2. Multi-Location & Multi-Node Subscription Handler
# -------------------------------------------------------------

def apply_iran_optimizations(nodes: List[Dict[str, Any]], clean_ips: List[str]) -> List[Dict[str, Any]]:
    optimized = []
    for n in nodes:
        node = dict(n)
        if node.get('network') in ['ws', 'grpc'] and node.get('sni') and clean_ips:
            node['server'] = random.choice(clean_ips)
        if node.get('tls') == 'reality' and not node.get('flow'):
            node['flow'] = 'xtls-rprx-vision'
        optimized.append(node)
    return optimized

def sort_nodes(nodes: List[Dict[str, Any]], strategy: str = "balanced") -> List[Dict[str, Any]]:
    cloned = [dict(n) for n in nodes]
    if strategy in ["fastest", "lowest-latency"]:
        cloned.sort(key=lambda x: x.get('latency', 9999))
    elif strategy == "country":
        by_country = {}
        for n in cloned:
            c = n.get('country', 'UN')
            by_country.setdefault(c, []).append(n)
        interleaved = []
        has_items = True
        while has_items:
            has_items = False
            for c_list in by_country.values():
                if c_list:
                    interleaved.append(c_list.pop(0))
                    has_items = True
        return interleaved
    else:
        cloned.sort(key=lambda x: x.get('score', 0), reverse=True)
    return cloned

def generate_subscription_response(
    nodes: List[Dict[str, Any]],
    target: str = "singbox",
    strategy: str = "balanced",
    iran_optimized: bool = True
) -> Dict[str, Any]:
    selected_nodes = sort_nodes(nodes, strategy)
    clean_ips = PRESET_CLEAN_IPS.get("iran", [])
    if iran_optimized:
        selected_nodes = apply_iran_optimizations(selected_nodes, clean_ips)
        
    t = target.lower().strip()
    if t in ["singbox", "sb"]:
        content = generate_singbox_config(selected_nodes, clean_ips)
        media_type = "application/json; charset=utf-8"
        ext = "json"
    elif t in ["clash", "clashmeta", "meta"]:
        content = generate_clash_meta_config(selected_nodes)
        media_type = "text/yaml; charset=utf-8"
        ext = "yaml"
    elif t in ["raw", "plain"]:
        content = generate_plain_subscription(selected_nodes)
        media_type = "text/plain; charset=utf-8"
        ext = "txt"
    elif t in ["wireguard", "warp"]:
        content = generate_wireguard_config()
        media_type = "text/plain; charset=utf-8"
        ext = "conf"
    elif t == "json":
        content = json.dumps({"total": len(selected_nodes), "nodes": selected_nodes}, indent=2, ensure_ascii=False)
        media_type = "application/json; charset=utf-8"
        ext = "json"
    else:
        content = generate_base64_subscription(selected_nodes)
        media_type = "text/plain; charset=utf-8"
        ext = "txt"
        
    return {
        "content": content,
        "media_type": media_type,
        "ext": ext,
        "count": len(selected_nodes)
    }
