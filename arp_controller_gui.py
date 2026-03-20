#!/usr/bin/env python3
"""
内网ARP控制器 - GUI版本 (Windows)
仅供合法内网管理使用
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import struct
import subprocess
import threading
import time
import os
import sys
import uuid

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
    node = uuid.getnode()
    mac = ':'.join(['{:02x}'.format((node >> i) & 0xff) for i in range(0, 48, 8)][::-1])
    return mac

def get_gateway():
    try:
        result = subprocess.run(['route', 'print', '0.0.0.0'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            if '0.0.0.0' in line and not line.strip().startswith('0.0.0.0'):
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    except:
        pass
    local_ip = get_local_ip()
    return '.'.join(local_ip.split('.')[:3]) + '.1'

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout
    except:
        return ""

def ping_host(ip, timeout=1):
    try:
        cmd = f'ping -n 1 -w {timeout*1000} {ip}'
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout+1)
        return result.returncode == 0
    except:
        return False

# ============== 主程序类 ==============
class ARPGuiController:
    def __init__(self, root):
        self.root = root
        self.root.title("内网控制器 v1.0")
        self.root.geometry("800x600")
        
        self.scanned_ips = []
        self.blocked_ips = []
        self.stop_scan = threading.Event()
        self.stop_block = threading.Event()
        
        self.setup_ui()
        self.auto_detect_network()
    
    def setup_ui(self):
        # 顶部信息栏
        info_frame = ttk.Frame(self.root)
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text="本机IP:").grid(row=0, column=0, sticky=tk.W)
        self.local_ip_label = ttk.Label(info_frame, text="检测中...", foreground='blue')
        self.local_ip_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(info_frame, text="网关:").grid(row=0, column=2, sticky=tk.W, padx=(20,0))
        self.gateway_label = ttk.Label(info_frame, text="检测中...", foreground='blue')
        self.gateway_label.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # 扫描区域
        scan_frame = ttk.LabelFrame(self.root, text="网络扫描", padding=10)
        scan_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(scan_frame, text="网段:").grid(row=0, column=0, sticky=tk.W)
        self.subnet_entry = ttk.Entry(scan_frame, width=15)
        self.subnet_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        self.scan_btn = ttk.Button(scan_frame, text="开始扫描", command=self.start_scan)
        self.scan_btn.grid(row=0, column=2, padx=5)
        
        self.progress = ttk.Progressbar(scan_frame, mode='determinate', length=200)
        self.progress.grid(row=0, column=3, padx=10)
        
        ttk.Label(scan_frame, text="状态:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.status_label = ttk.Label(scan_frame, text="就绪", foreground='green')
        self.status_label.grid(row=1, column=1, columnspan=3, sticky=tk.W)
        
        # 在线设备列表
        list_frame = ttk.LabelFrame(self.root, text="在线设备", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 设备列表 (Treeview)
        columns = ('ip', 'status')
        self.device_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=8)
        self.device_tree.heading('ip', text='IP地址')
        self.device_tree.heading('status', text='状态')
        self.device_tree.column('ip', width=200)
        self.device_tree.column('status', width=100)
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        
        # 选中提示
        self.selection_label = ttk.Label(list_frame, text="未选中设备", foreground='gray')
        self.selection_label.pack(anchor=tk.W)
        self.device_tree.bind('<<TreeviewSelect>>', self.on_device_select)
        
        # 控制区域
        control_frame = ttk.LabelFrame(self.root, text="设备控制", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="阻断时长(秒):").grid(row=0, column=0, sticky=tk.W)
        self.duration_spin = ttk.Spinbox(control_frame, from_=10, to=3600, width=10)
        self.duration_spin.set(60)
        self.duration_spin.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        self.block_btn = ttk.Button(control_frame, text="阻断选中设备", command=self.block_selected, state=tk.DISABLED)
        self.block_btn.grid(row=0, column=2, padx=10)
        
        self.unblock_btn = ttk.Button(control_frame, text="解除阻断", command=self.unblock_selected, state=tk.DISABLED)
        self.unblock_btn.grid(row=0, column=3, padx=10)
        
        self.batch_block_btn = ttk.Button(control_frame, text="批量阻断全部", command=self.block_all, state=tk.DISABLED)
        self.batch_block_btn.grid(row=0, column=4, padx=10)
        
        # 日志区域
        log_frame = ttk.LabelFrame(self.root, text="操作日志", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 底部按钮
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(bottom_frame, text="刷新网络信息", command=self.auto_detect_network).pack(side=tk.LEFT)
        ttk.Button(bottom_frame, text="清空日志", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom_frame, text="导出IP列表", command=self.export_ips).pack(side=tk.LEFT)
    
    def auto_detect_network(self):
        local_ip = get_local_ip()
        gateway = get_gateway()
        
        self.local_ip_label.config(text=local_ip)
        self.gateway_label.config(text=gateway)
        
        # 自动填充网段
        subnet = '.'.join(local_ip.split('.')[:3])
        self.subnet_entry.delete(0, tk.END)
        self.subnet_entry.insert(0, subnet)
        
        self.log(f"网络信息: 本机IP={local_ip}, 网关={gateway}")
    
    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def on_device_select(self, event):
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            ip = item['values'][0]
            status = item['values'][1]
            self.selection_label.config(text=f"选中: {ip} ({status})")
            self.block_btn.config(state=tk.NORMAL)
            self.unblock_btn.config(state=tk.NORMAL if status == "已阻断" else tk.DISABLED)
        else:
            self.selection_label.config(text="未选中设备")
            self.block_btn.config(state=tk.DISABLED)
            self.unblock_btn.config(state=tk.DISABLED)
    
    def start_scan(self):
        subnet = self.subnet_entry.get().strip()
        if not subnet:
            messagebox.showwarning("警告", "请输入网段")
            return
        
        self.scan_btn.config(state=tk.DISABLED)
        self.status_label.config(text="扫描中...", foreground='orange')
        self.progress['value'] = 0
        
        # 清空列表
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        self.scanned_ips = []
        
        self.stop_scan.clear()
        thread = threading.Thread(target=self.scan_worker, args=(subnet,))
        thread.daemon = True
        thread.start()
    
    def scan_worker(self, subnet):
        targets = [f"{subnet}.{i}" for i in range(1, 255)]
        total = len(targets)
        completed = 0
        found = 0
        
        for ip in targets:
            if self.stop_scan.is_set():
                break
            
            if ping_host(ip, timeout=1):
                self.scanned_ips.append(ip)
                found += 1
                self.root.after(0, self.add_device, ip, "在线")
                self.root.after(0, self.log, f"发现设备: {ip}")
            
            completed += 1
            progress = (completed / total) * 100
            self.root.after(0, self.progress.configure, {'value': progress})
        
        self.root.after(0, self.scan_complete, found)
    
    def add_device(self, ip, status):
        self.device_tree.insert('', tk.END, values=(ip, status))
    
    def scan_complete(self, count):
        self.scan_btn.config(state=tk.NORMAL)
        self.status_label.config(text=f"扫描完成，发现 {count} 台设备", foreground='green')
        self.progress['value'] = 100
        self.batch_block_btn.config(state=tk.NORMAL if count > 0 else tk.DISABLED)
    
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
        self.block_devices(ips_to_block, duration)
    
    def block_all(self):
        if not self.scanned_ips:
            return
        
        try:
            duration = int(self.duration_spin.get())
        except:
            duration = 60
        
        self.log(f"批量阻断 {len(self.scanned_ips)} 个设备")
        self.block_devices(self.scanned_ips, duration)
    
    def unblock_selected(self):
        selection = self.device_tree.selection()
        if not selection:
            return
        
        for item in selection:
            ip = self.device_tree.item(item)['values'][0]
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                self.device_tree.item(item, values=(ip, "在线"))
                self.log(f"解除阻断: {ip}")
        
        self.unblock_btn.config(state=tk.DISABLED)
    
    def block_devices(self, ips, duration):
        """使用防火墙规则阻断"""
        rules = []
        
        for ip in ips:
            rule_name = f"BLOCK_{ip.replace('.', '_')}"
            # 检查规则是否已存在
            check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
            result = run_cmd(check_cmd)
            
            if "No rules match" in result or not result:
                # 创建规则
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                run_cmd(cmd)
                rules.append(rule_name)
                self.log(f"已阻断: {ip}")
            
            # 更新列表状态
            for item in self.device_tree.get_children():
                if self.device_tree.item(item)['values'][0] == ip:
                    self.device_tree.item(item, values=(ip, "已阻断"))
                    if ip not in self.blocked_ips:
                        self.blocked_ips.append(ip)
        
        self.log(f"阻断设置完成，时长 {duration} 秒")
        
        # 定时解除
        def unblock_after_delay():
            time.sleep(duration)
            for rule_name in rules:
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                run_cmd(cmd)
            
            # 更新列表状态
            for ip in ips:
                if ip in self.blocked_ips:
                    self.blocked_ips.remove(ip)
                for item in self.device_tree.get_children():
                    if self.device_tree.item(item)['values'][0] == ip:
                        self.device_tree.item(item, values=(ip, "在线"))
            
            self.root.after(0, self.log, f"已自动解除阻断: {', '.join(ips)}")
        
        thread = threading.Thread(target=unblock_after_delay, daemon=True)
        thread.start()
    
    def export_ips(self):
        if not self.scanned_ips:
            messagebox.showinfo("提示", "没有可导出的IP")
            return
        
        filename = f"ip_list_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            for ip in self.scanned_ips:
                f.write(f"{ip}\n")
        
        messagebox.showinfo("导出成功", f"已导出到: {filename}")

# ============== 启动 ==============
def main():
    root = tk.Tk()
    
    # 设置样式
    style = ttk.Style()
    style.theme_use('clam')
    
    app = ARPGuiController(root)
    root.mainloop()

if __name__ == '__main__':
    main()