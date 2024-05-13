import os
import json
import requests
import random


from ..log4ck import success, error
from ..connect import pandora_box
from ..util import save2file, save2json, get_the_current_date


class Awd:
    def __init__(self, *, hosts_file: str = "", ips_file: str = "", ports_file: str = "",
                 static_ip: str = "", static_port: int = 0,
                 hosts: list = None, ips: list = None, ports: list = None,
                 binary: str = "", remote_libc: str = "",
                 headers: dict = None, token: str = "", api_address: str = "",
                 exploit=None,
                 logs_path: str = "", flags_path: str = "", flags_file_name_sign: str = int(random.randint(0, 65535))):
        """
        Initialize the AWD object.
        :param hosts_file:
        :param ips_file:
        :param ports_file:
        :param hosts:
        :param ips:
        :param ports:
        :param binary:
        :param remote_libc:
        :param headers:
        :param token:
        :param api_address:
        :param exploit:
        :param logs_path:
        :param flags_path:
        """

        self.hosts_file = hosts_file
        self.ips_file = ips_file
        self.ports_file = ports_file

        self.static_ip = static_ip
        self.static_port = static_port

        self.hosts = hosts if hosts is not None else []
        self.ips = ips if ips is not None else []
        self.ports = ports if ports is not None else []

        self.binary = binary
        self.remote_libc = remote_libc

        self.headers = headers if headers is not None else {}
        self.token = token
        self.api_address = api_address

        self.exploit = exploit

        self.logs_path = logs_path
        self.flags_path = flags_path

        self.flags_file_name_sign = flags_file_name_sign

        self.flags = []

    def set_hosts_and_ip_ports(self) -> list:

        addresses = self.hosts

        if os.path.exists(self.hosts_file):
            hosts_path = self.hosts_file

            try:
                with open(hosts_path, 'r') as file:
                    for line in file:
                        # 移除行尾的换行符
                        line = line.strip()
                        # 按照空格或者冒号分割，提取 IP 和端口号
                        parts = line.split(':') if ':' in line else line.split()
                        # 检查是否有端口号
                        if len(parts) == 2:
                            address = (parts[0], int(parts[1]))  # 将端口号转换为整数
                            addresses.append(address)
                        elif len(parts) == 1:
                            address = (parts[0], None)  # 没有指定端口号，设置为 None
                            addresses.append(address)
            except Exception as ex:
                error(f"{str(ex) = }")
                exit(0)
        else:
            error(f"No such file or directory --> File Name: {self.hosts_file}")

            if os.path.exists(self.ips_file) and os.path.exists(self.ports_file):

                ips_path = self.ips_file
                ports_path = self.ports_file

                try:
                    with open(ips_path, 'r') as file:
                        for line in file:
                            ip = line.strip()
                            self.ips.append(ip)
                    with open(ports_path, 'r') as file:
                        for line in file:
                            port = line.strip()
                            self.ports.append(port)

                    for i in range(min(len(self.ips), len(self.ports))):
                        address = (self.ips[i], int(self.ports[i]))
                        addresses.append(address)

                except Exception as ex:
                    error(f"{str(ex) = }")
                    exit(0)

            elif os.path.exists(self.ips_file) and self.static_port != 0:
                ips_path = self.ips_file
                try:
                    with open(ips_path, 'r') as file:
                        for line in file:
                            ip = line.strip()
                            self.ips.append(ip)

                    for i in range(len(self.ips)):
                        address = (self.ips[i], self.static_port)
                        addresses.append(address)
                except Exception as ex:
                    error(f"{str(ex) = }")
                    exit(0)

            elif os.path.exists(self.ports_file) and self.static_ip != "":
                ports_path = self.ports_file

                try:
                    with open(ports_path, 'r') as file:
                        for line in file:
                            port = line.strip()
                            self.ports.append(port)

                    for i in range(len(self.ports)):
                        address = (self.static_ip, int(self.ports[i]))
                        addresses.append(address)
                except Exception as ex:
                    error(f"{str(ex) = }")
                    exit(0)

        print(addresses)

        self.hosts = addresses
        return self.hosts

    def send_flag_to_api_address(self, *, flag: str = "", datas: dict = None, method: str = "POST"):

        if self.token != "":
            if self.headers is None:
                self.headers = {'Authorization': f'Bearer {self.token}'}
            else:
                self.headers['Authorization'] = f'Bearer {self.token}'

        if method.upper() == "POST":
            if datas is None and flag != "":
                datas = {
                    "flag": flag
                }

            requests.post(url=self.api_address, headers=self.headers, data=json.dumps(datas))

    def save_flag_to_flag_file(self, host, flag, file_format: str = "json"):

        flag_folder_path = get_the_current_date("path")
        flag_file_name = get_the_current_date("path") + "_" + self.flags_file_name_sign

        flags_path = os.path.join(self.flags_path, flag_folder_path) + "/"

        new_host = host[0] + str(host[1])
        if file_format.lower() == "txt":
            datas = new_host + " " + flag.decode()

            save2file(flags_path,
                      flag_file_name + ".txt",
                      datas)
        elif file_format.lower() == "json":
            datas = {
                new_host: flag.decode()
            }

            save2json(flags_path,
                      flag_file_name + ".json",
                      datas)

    def attack(self, *, print_flag: bool = True, send_flag: bool = True, save_flag: bool = True):

        self.set_hosts_and_ip_ports()
        for host in self.hosts:
            pandora_box.update_script(local=False, binary_path=self.binary,
                                      ip=host[0], port=host[1],
                                      remote_libc_path=self.remote_libc)

            flag = self.exploit()
            self.flags.append(flag)

            if print_flag:
                success(f"{str(host)} -> {str(flag)}")

            if send_flag:
                self.send_flag_to_api_address(flag=flag)

            if save_flag:
                self.save_flag_to_flag_file(host, flag)

        if print_flag:
            for i in range(len(self.flags)):
                success(f"{self.hosts[i]} -> {self.flags[i]}")
