#!/usr/bin/env python3
"""
内网ARP控制器 - GUI版本 (Windows)
仅供合法内网管理使用
依赖: customtkinter scapy requests
"""

import customtkinter as ctk
from tkinter import messagebox
import requests
import threading
import time
import os
import sys
import socket
import uuid

# 尝试导入scapy (可能需要管理员权限)
try:
    from scapy.all import ARP, Ether, srp, send, conf
    conf.verb = 0  # 禁用scapy verbose输出
    HAS_SCAPY = True
except:
    HAS_SCAPY = False

# ============== 配置 ==============
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ============== 工具函数 ==============
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

def get_local_mac():
    """获取本机MAC"""
    if sys.platform == 'win32':
        node = uuid.getnode()
        mac = ':'.join(['{:02x}'.format((node >> i) & 0xff) for i in range(0, 48, 8)][::-1])
        return mac
    else:
        try:
            with open('/sys/class/net/eth0/address', 'r') as f:
                return f.read().strip()
        except:
            return '00:00:00:00:00:00'

def get_gateway():
    """获取网关IP"""
    try:
        if sys.platform == 'win32':
            import subprocess
            result = subprocess.run(['route', 'print', '0.0.0.0'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if '0.0.0.0' in line and not line.strip().startswith('0.0.0.0'):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
        else:
            with open('/proc/net/route', 'r') as f:
                for line in f:
                    parts = line.split()
                    if parts[1] == '00000000':
                        return socket.inet_ntoa(int(parts[2], 16).to_bytes(4, 'little'))
    except:
        pass
    local_ip = get_local_ip()
    return '.'.join(local_ip.split('.')[:3]) + '.1'

def ping_host(ip, timeout=1):
    """Ping检测主机"""
    try:
        import subprocess
        if sys.platform == 'win32':
            cmd = f'ping -n 1 -w {timeout*1000} {ip}'
        else:
            cmd = f'ping -c 1 -W {timeout} {ip}'
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout+1)
        return result.returncode == 0
    except:
        return False

def scan_with_scapy(subnet):
    """使用Scapy扫描网络"""
    gateway_ip = get_gateway()
    # 构建ARP请求
    arp = ARP(pdst=f"{subnet}.1/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    
    result = srp(packet, timeout=3, verbose=False)[0]
    
    devices = []
    for sent, received in result:
        if received.psrc != gateway_ip:  # 排除网关
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def scan_with_ping(subnet):
    """使用Ping扫描网络"""
    devices = []
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        if ping_host(ip, timeout=0.5):
            devices.append({'ip': ip, 'mac': 'Unknown'})
    return devices

# ============== 主程序类 ==============
class ARPGuiController(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("内网控制器 v2.0")
        self.geometry("900x650")
        
        self.scanned_devices = []
        self.blocked_ips = []
        self.gateway_ip = ""
        
        self.setup_ui()
        self.auto_detect_network()
    
    def setup_ui(self):
        # 网格布局
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # 左侧边栏
        sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        sidebar.grid(row=0, column=0, rowspan=4, sticky="nsew")
        sidebar.grid_rowconfigure(10, weight=1)
        
        ctk.CTkLabel(sidebar, text="内网控制器", font=("Arial", 20, "bold")).grid(row=0, column=0, padx=20, pady=20)
        
        # 网络信息
        ctk.CTkLabel(sidebar, text="本机IP:", text_color="gray").grid(row=1, column=0, padx=20, pady=(10,0), sticky="w")
        self.local_ip_label = ctk.CTkLabel(sidebar, text="检测中...")
        self.local_ip_label.grid(row=2, column=0, padx=20, sticky="w")
        
        ctk.CTkLabel(sidebar, text="网关:", text_color="gray").grid(row=3, column=0, padx=20, pady=(10,0), sticky="w")
        self.gateway_label = ctk.CTkLabel(sidebar, text="检测中...")
        self.gateway_label.grid(row=4, column=0, padx=20, sticky="w")
        
        ctk.CTkLabel(sidebar, text="Scapy状态:", text_color="gray").grid(row=5, column=0, padx=20, pady=(10,0), sticky="w")
        scapy_status = "已安装" if HAS_SCAPY else "未安装"
        scapy_color = "green" if HAS_SCAPY else "red"
        self.scapy_label = ctk.CTkLabel(sidebar, text=scapy_status, text_color=scapy_color)
        self.scapy_label.grid(row=6, column=0, padx=20, sticky="w")
        
        # 功能按钮
        ctk.CTkButton(sidebar, text="刷新网络", command=self.auto_detect_network).grid(row=7, column=0, padx=20, pady=20)
        ctk.CTkButton(sidebar, text="清空日志", command=self.clear_log).grid(row=8, column=0, padx=20, pady=5)
        ctk.CTkButton(sidebar, text="导出IP列表", command=self.export_ips).grid(row=9, column=0, padx=20, pady=5)
        
        # 主内容区
        # 扫描控制
        scan_frame = ctk.CTkFrame(self)
        scan_frame.grid(row=0, column=1, padx=20, pady=20, sticky="ew")
        
        ctk.CTkLabel(scan_frame, text="网段:").grid(row=0, column=0, padx=10)
        self.subnet_entry = ctk.CTkEntry(scan_frame, width=150)
        self.subnet_entry.grid(row=0, column=1, padx=5)
        
        self.scan_btn = ctk.CTkButton(scan_frame, text="开始扫描", command=self.start_scan, width=120)
        self.scan_btn.grid(row=0, column=2, padx=10)
        
        self.progress = ctk.CTkProgressBar(scan_frame, width=300)
        self.progress.grid(row=0, column=3, padx=10)
        self.progress.set(0)
        
        ctk.CTkLabel(scan_frame, text="状态:").grid(row=1, column=0, padx=10, pady=10)
        self.status_label = ctk.CTkLabel(scan_frame, text="就绪", text_color="green")
        self.status_label.grid(row=1, column=1, columnspan=3, pady=10, sticky="w")
        
        # 设备列表
        list_frame = ctk.CTkFrame(self)
        list_frame.grid(row=1, column=1, padx=20, pady=10, sticky="nsew")
        
        ctk.CTkLabel(list_frame, text="在线设备", font=("Arial", 14, "bold")).pack(pady=10)
        
        # 表格
        columns = ('ip', 'mac', 'status')
        self.device_tree = ctk.CTkTreeview(list_frame, columns=columns, show='headings', height=12)
        self.device_tree.heading('ip', text='IP地址')
        self.device_tree.heading('mac', text='MAC地址')
        self.device_tree.heading('status', text='状态')
        self.device_tree.column('ip', width=150)
        self.device_tree.column('mac', width=180)
        self.device_tree.column('status', width=100)
        self.device_tree.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 选中事件
        self.device_tree.bind('<<TreeviewSelect>>', self.on_device_select)
        
        # 控制区
        control_frame = ctk.CTkFrame(self)
        control_frame.grid(row=2, column=1, padx=20, pady=10, sticky="ew")
        
        ctk.CTkLabel(control_frame, text="阻断时长(秒):").grid(row=0, column=0, padx=10)
        self.duration_spin = ctk.CTkEntry(control_frame, width=80)
        self.duration_spin.insert(0, "60")
        self.duration_spin.grid(row=0, column=1, padx=5)
        
        self.block_btn = ctk.CTkButton(control_frame, text="阻断选中", command=self.block_selected, state="disabled", width=120)
        self.block_btn.grid(row=0, column=2, padx=10)
        
        self.unblock_btn = ctk.CTkButton(control_frame, text="解除阻断", command=self.unblock_selected, state="disabled", width=120)
        self.unblock_btn.grid(row=0, column=3, padx=10)
        
        self.batch_block_btn = ctk.CTkButton(control_frame, text="批量阻断全部", command=self.block_all, state="disabled", fg_color="red", hover_color="darkred", width=140)
        self.batch_block_btn.grid(row=0, column=4, padx=10)
        
        # 日志区
        log_frame = ctk.CTkFrame(self)
        log_frame.grid(row=3, column=1, padx=20, pady=10, sticky="nsew")
        
        ctk.CTkLabel(log_frame, text="操作日志", font=("Arial", 14, "bold")).pack(pady=10)
        
        self.log_text = ctk.CTkTextbox(log_frame, height=120)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(0,10))
    
    def auto_detect_network(self):
        local_ip = get_local_ip()
        gateway = get_gateway()
        local_mac = get_local_mac()
        
        self.local_ip_label.configure(text=local_ip)
        self.gateway_label.configure(text=gateway)
        self.gateway_ip = gateway
        
        # 自动填充网段
        subnet = '.'.join(local_ip.split('.')[:3])
        self.subnet_entry.delete(0, "end")
        self.subnet_entry.insert(0, subnet)
        
        self.log(f"网络信息: 本机IP={local_ip}, MAC={local_mac}, 网关={gateway}")
    
    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
    
    def clear_log(self):
        self.log_text.delete("1.0", "end")
    
    def on_device_select(self, event):
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            ip = item['values'][0]
            status = item['values'][2]
            self.block_btn.configure(state="normal")
            self.unblock_btn.configure(state="normal" if status == "已阻断" else "disabled")
        else:
            self.block_btn.configure(state="disabled")
            self.unblock_btn.configure(state="disabled")
    
    def start_scan(self):
        subnet = self.subnet_entry.get().strip()
        if not subnet:
            messagebox.showwarning("警告", "请输入网段")
            return
        
        self.scan_btn.configure(state="disabled", text="扫描中...")
        self.status_label.configure(text="扫描中...", text_color="orange")
        self.progress.set(0)
        
        # 清空列表
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        self.scanned_devices = []
        
        thread = threading.Thread(target=self.scan_worker, args=(subnet,))
        thread.daemon = True
        thread.start()
    
    def scan_worker(self, subnet):
        try:
            # 优先使用scapy
            if HAS_SCAPY:
                self.log("使用Scapy扫描...")
                devices = scan_with_scapy(subnet)
            else:
                self.log("使用Ping扫描...")
                devices = scan_with_ping(subnet)
            
            for dev in devices:
                self.scanned_devices.append(dev)
                self.after(0, self.add_device, dev['ip'], dev.get('mac', 'Unknown'), "在线")
                self.after(0, self.log, f"发现设备: {dev['ip']} ({dev.get('mac', 'Unknown')})")
            
            self.after(0, self.scan_complete, len(devices))
        except Exception as e:
            self.after(0, self.log, f"扫描错误: {e}")
            self.after(0, self.scan_btn.configure, {"state": "normal", "text": "开始扫描"})
    
    def add_device(self, ip, mac, status):
        self.device_tree.insert('', 'end', values=(ip, mac, status))
    
    def scan_complete(self, count):
        self.scan_btn.configure(state="normal", text="开始扫描")
        self.status_label.configure(text=f"扫描完成，发现 {count} 台设备", text_color="green")
        self.progress.set(1)
        self.batch_block_btn.configure(state="normal" if count > 0 else "disabled")
    
    def block_selected(self):
        selection = self.device_tree.selection()
        if not selection:
            return
        
        try:
            duration = int(self.duration_spin.get())
        except:
            duration = 60
        
        ips_to_block = []
        for item in selection:
            ip = self.device_tree.item(item)['values'][0]
            ips_to_block.append(ip)
        
        self.log(f"开始阻断: {', '.join(ips_to_block)}")
        
        # 使用防火墙阻断
        self.block_with_firewall(ips_to_block, duration)
    
    def block_all(self):
        if not self.scanned_devices:
            return
        
        try:
            duration = int(self.duration_spin.get())
        except:
            duration = 60
        
        ips = [d['ip'] for d in self.scanned_devices]
        self.log(f"批量阻断 {len(ips)} 个设备")
        self.block_with_firewall(ips, duration)
    
    def block_with_firewall(self, ips, duration):
        """使用Windows防火墙阻断"""
        import subprocess
        
        rules = []
        for ip in ips:
            rule_name = f"BLOCK_{ip.replace('.', '_')}"
            try:
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                rules.append(rule_name)
                
                # 更新UI
                for item in self.device_tree.get_children():
                    if self.device_tree.item(item)['values'][0] == ip:
                        self.device_tree.item(item, values=(ip, self.device_tree.item(item)['values'][1], "已阻断"))
                        if ip not in self.blocked_ips:
                            self.blocked_ips.append(ip)
                
                self.log(f"已阻断: {ip}")
            except Exception as e:
                self.log(f"阻断失败: {ip} - {e}")
        
        self.log(f"阻断设置完成，时长 {duration} 秒")
        
        # 定时解除
        def unblock_after_delay():
            time.sleep(duration)
            for rule_name in rules:
                try:
                    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                    subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                except:
                    pass
            
            for ip in ips:
                if ip in self.blocked_ips:
                    self.blocked_ips.remove(ip)
                for item in self.device_tree.get_children():
                    if self.device_tree.item(item)['values'][0] == ip:
                        self.device_tree.item(item, values=(ip, self.device_tree.item(item)['values'][1], "在线"))
            
            self.after(0, self.log, f"已自动解除阻断: {', '.join(ips)}")
        
        thread = threading.Thread(target=unblock_after_delay, daemon=True)
        thread.start()
    
    def unblock_selected(self):
        selection = self.device_tree.selection()
        if not selection:
            return
        
        for item in selection:
            values = self.device_tree.item(item)['values']
            ip = values[0]
            mac = values[1]
            
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                self.device_tree.item(item, values=(ip, mac, "在线"))
                self.log(f"解除阻断: {ip}")
    
    def export_ips(self):
        if not self.scanned_devices:
            messagebox.showinfo("提示", "没有可导出的IP")
            return
        
        filename = f"ip_list_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            for dev in self.scanned_devices:
                f.write(f"{dev['ip']},{dev.get('mac', 'Unknown')}\n")
        
        messagebox.showinfo("导出成功", f"已导出到: {filename}")

# ============== 启动 ==============
def main():
    app = ARPGuiController()
    app.mainloop()

if __name__ == '__main__':
    main()