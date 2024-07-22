config_entity = {
    'config_filename': '',                          # conf_file.cfg
    'hostname': '',                                 # ciscodevice-1.device
    'domain_name': '',                              # ciscodevice-1.ru
    'mgmt_ipv4_from_filename': '',                  # 192.168.0.1
    'mgmt_v4_autodetect': '',                       # 192.168.0.1
    'mgmt_v6_autodetect': '',                       # 192::1
    'vendor': '',                                   # Cisco Systems
    'vendor_id': '',                                # cisco
    'model': '',                                    # C9300-48T
    'family': '',                                   # cisco_catalyst, cisco_isr, cisco_nexus, arista_switch, cisco_vrouter, huawei_ce, huawei_s, huawei_ar, hpe_switch, hpe_switch2, hpe_aruba_switch
    'os': '',                                       # cisco_ios_xe, cisco_ios, cisco_ios_xr, arista_eos, cisco_nx_os, aruba_aos-s, hpe_os, huawei_vrp, hpe_comware
    'serial': '',                                   # FDO1719Z0PZ
    'sw_version': '',                               # 15.2(7)E4
    'name_server': [],                              # ['10.2.51.71','10.2.51.71']
    'ntp_server': [],                               # ['10.2.51.71', '10.2.51.71']
    'vtp_version': '',                              # {1, 2, 3}
    'vtp_domain_name': '',                          # domain name
    'vtp_oper_mode': '',                            # {transparent, server, client, off}
    'vtp_revision': '',                             # 0....N
    'snmp_ver': "",                                 # v3c
    'spanning-tree': '',                            # rapid-pvst
    'vrf': [],                                      # {'name': 'management', 'rt': '65000', 'rd': '50'}
    'vlans': {},                                    # {'id': '10', 'name': 'default'}
    'devices': [],                                  # {'model': 'C9300-48T', 'serial': 'C9300-48T', 'sw_version': 'C9300-48T'}
    'inventory': [],                                # {'type': 'Chassis', 'description': 'Cisco ISR4321 Chassis', 'part': 'ISR4321/K9', 'serial_num': 'FDO2522M0EN'}
    'licenses': [],                                 # {'technology': 'appxk9', 'currently': 'None', 'type': 'None', 'next_reboot': 'None'}
    'license_suite': [],                            # {'suite': 'FoundationSuiteK9', 'currentl_suite': 'None', 'type': 'RightToUse', 'suite_next_reboot': 'FoundationSuiteK9'}
    'throughput_level': '',                         # 100000 - from license, if any
    'interfaces': [],
    'default-gateway': '',                          # 10.2.254.1
    'routing_table': [],                            # {'dest_net': '192.168.0.0/24', 'protocol': 'static', 'vrf': 'vrf_name'}
    'bgp_l2vpn_table': [],                          # {'vrf': 'default', 'status': 'valid|suppressed|damped|history|best|multipath|internal|RIBFail|Stale|Removed', 'network': '0.0.0.0/0', 'next-hop': '100.64.4.130', 'next-hop-self': 'yes', 'metric': '0', 'local_pref': '50', 'weight': '0', 'as-path': '4292608010 4292608012', 'origin': 'IGP|EGP|incomplete'}
    'mac_table': [],                                # {'vlan': 'vlan_id', 'mac': 'aa:aa:aa:aa:aa:aa', 'type': 'static', 'interface': 'Gi1/0/3'}
    'arp_table': [],                                # {'address': '192.168.0.1', 'mac': 'aa:aa:aa:aa:aa:aa', 'interface': 'static'}
    'esi_table': [],                                # {'esi': '03:aa:1c:73:00:01:01:00:00:65', 'type': 'R', 'port': 'PortChannel1', 'status': 'up', 'vteps': '192.168.1'}
    'ip_nei_table': [],                             # {'ip': '03:aa:1c:73:00:01', 'dev': 'Sag122', 'lladdr': '52:54:00:c7:17:ee', 'learned': 'extern_learn', 'used': 'used 67827/67827/67827', 'probes': '0', 'status': 'NOARP', 'proto': 'zebra'}
    'cdp_neighbours': [],                           # {'device_id': 'asw-1.ru', 'ip_addr': '192.168.1', 'model': 'cisco 9200L-24T-4G', 'local_interface': 'GigabitEthernet0/0/0', 'remote_interface': 'GigabitEthernet0/0/0'}
    'logging_host': [],                             # '10.66.228.33', '10.10.248.70'
    'tacacs_servers': [],                           # '10.66.228.33', '10.66.228.33'
    'snmp_server_group': '',                        # SNMP_Group
    'snmp_community': '',                           # SNMP Community
    'ssh_ver': '',                                  # 2
    'line_con': [],                                 # {'number': 'num', 'transport_input': 'ssh', 'transport_output': 'none', 'logging': 'synchronous', 'exec-timeout': '60 0', 'password': '7', 'secret': '7', 'access_class': '', 'auth_exec': 'ISE', 'login_auth': 'ISE'}
    'line_aux': [],                                 # {'number': 'num', 'transport_input': 'ssh', 'transport_output': 'none', 'logging': 'synchronous', 'exec-timeout': '60 0', 'password': '7', 'secret': '7', 'access_class': '', 'auth_exec': 'ISE', 'login_auth': 'ISE'}
    'line_vty': [],                                 # {'number': 'num', 'transport_input': 'ssh', 'transport_output': 'none', 'transport_preferred': 'none', 'logging': 'synchronous', 'exec-timeout': '60 0', 'password': '7', 'secret': '7', 'access_class': '', 'auth_exec': 'ISE', 'login_auth': 'ISE'}
    'errors': [],
    'known_errors': '',                             # number of well-known errors
    'all_errors': '',                               # number of all errors (\sERR\s prefix in logs)
    'ecmp_groups': '',                              # actual number of ECMP Groups
    'hosts': '',                                    # actual number of HOSTS
    'next_hops': '',                                # actual number of NEXT HOPS
    'routes': ''                                    # actual number of routes
}


interface_entity = {
    'name': '',                                     # gi0/1
    'description': '',                              # First_interface
    'type': '',                                     # ethernet, serial, svi, po, tunnel, loopback, not set
    'physical_type': '',                            # 1000BaseT, SFP-10GBase-LR, 1000BaseLX SFP, SFP-10GBase-CU3M
    'actual_speed': '',                             # actual speed, i.e. a-1000 = 1G, 25G, 1000, 10G, 100G
    'ipv4': [],                                     # '20.20.20.2'
    'mgmt': "",                                     # no
    'status': '',                                   # connected, notconnect, up (for virtual interfaces)
    'vrf': '',                                      # GRT
    'switchport_mode': '',                          # access, trunk
    'dtp_mode': '',                                 # nonegotiate
    'access_vlan': '',                              # 100
    'portfast': '',                                 # yes
    'bpduguard': '',                                # yes
    'trunk_vlan_ids': [],                           # 10, 20
    'ip_helper': [],                                # '10.76.131.19', '10.76.131.20'
    'ip_redirects': '',                             # no
    'proxy_arp': '',                                # no
    'native_vlan': '',                              # 2
    'voice_vlan': '',                               # 3
    'channel_group': '',                            # 2
    'channel_group_mode': '',                       # active
    'mdix': '',                                     # auto
    'dot1x_mab': '',                                # mab
    'dot1x_auth_order': '',                         # mab dot1x
    'dot1x_auth_prio': '',                          # dot1x mab
    'dot1x_auth_port_control': ''                   # auto
}

cdp_record = {
    'local_id': '',
    'local_model': '',
    'local_ip_addr': '',
    'local_interface': '',
    'remote_id': '',
    'remote_model': '',
    'remote_ip_addr': '',
    'remote_interface': ''
    }

mac_record = {
    'vlan': '',
    'mac_address': '',
    'port': '',
    'type': ''
    }

arp_record = {
    'vlan': '',
    'mac_address': '',
    'port': '',
    'type': ''
    }


edgecore_log_errors = [
    'ERR\ssystemd\S*:\sFailed\sto\sstart\s\S*\scontainer.',
    'ERR\spython3:\s:-\sparseDatabaseConfig:\sSonic\sdatabase\sconfig\sfile\sdoesn',
    'ERR\sswss#orchagent:\s:-\smeta_generic_validation_remove:\sobject\s\S+\sreference\scount\sis\s\d',
    'ERR\sswss#orchagent:\s:-\sremoveNeighbor:\sFailed\sto\sremove\snext\shop',
    'ERR\sswss#orchagent:\s:-\shandleSaiRemoveStatus:\sEncountered\sfailure\sin\sremove\soperation,\sexiting\sorchagent,\sSAI\sAPI:\sSAI_API_NEIGHBOR,\sstatus:\sSAI_STATUS_INSUFFICIENT_RESOURCES',
    'ERR\sswss#orchagent:\s:-\screate:\screate\sstatus:\sSAI_STATUS_INSUFFICIENT_RESOURCES',
    'ERR\sswss#orchagent:\s:-\screate:\screate\sstatus:\sSAI_STATUS_TABLE_FULL',
    'ERR\sswss#orchagent:\s:-\sremoveNeighbor:\sFailed\sto\sremove\sneighbor',
    'ERR kernel:\s\S*\si801_smbus\s\S+\sSMBus\sis\sbusy',
    'ERR\ssyncd#syncd:\s\[none\]\sbrcm_sai_create_tunnel_es_member:\d+\stunnel\ses\smember\sreserve\sfailed\swith\serror',
    'ERR\ssyncd#syncd:\s:-\ssendApiResponse:\sapi\sSAI_COMMON_API_CREATE\sfailed\sin\ssyncd\smode:\sSAI_STATUS_INSUFFICIENT_RESOURCES',
    'ERR\ssyncd#syncd:\s:-\sprocessQuadEvent:\sattr:\sSAI_TUNNEL_ES_MEMBER_ATTR_IP:',
    'ERR\ssyncd#syncd:\s:-\sprocessQuadEvent:\sattr:\sSAI_TUNNEL_ES_MEMBER_ATTR_ES_ID:\soid:',
    'INFO\ssyncd#syncd:\s\[none\]\s_brcm_sai_nbr_create_ecmp_group:\d+\screate\segress\sfail\s*Table\sfull',
    'ERR\ssyncd#syncd:\s\[none\]\s_brcm_sai_nbr_mac_db_update:\d+\screate\segress\sfail\sTable\sfull',
    'WARNING\ssyncd#syncd:\s\[none\]\s_brcm_sai_nbr_create_ecmp_group:\d+\s+overlay\secmp\sgroup\sis\sfull',
    'INFO\ssyncd#\/supervisord:\ssyncd\smalloc\(\):\sinvalid\ssize',
    'ERR\ssyncd#syncd:\s\[none\]\sbrcm_sai_remove_neighbor_entry:\d+\sdestroy\secmp\segress\sobject\sfailed\swith\serror',
    'WARNING\ssyncd#syncd:\s[none]\s_brcm_sai_nbr_create_ecmp_group:\d+\soverlay\secmp\sgroup\sis\sfull',
    'WARNING\ssyncd#syncd:\s\[none\]\s_brcm_sai_nbr_create_ecmp_group:\d+\soverlay\secmp\sgroup\sis\sfull',
    'ERR\ssyncd#syncd:\s\[none\]\sbrcm_sai_create_route_entry:\d+\sL3\sroute\sadd\sfailed\swith\serror',
    'ERR\ssyncd#syncd:\s:-\ssendApiResponse:\sapi\sSAI_COMMON_API_BULK_CREATE\sfailed\sin\ssyncd\smode:\sSAI_STATUS_FAILURE',
    'INFO\sbgp#\/supervisord:\szebra\s\S+\s\S+\sZEBRA:\s\[\S*\]\[\S+\s\S+\]\sFailed to install Nexthop ID',
    'INFO\sswss#supervisord\s\S*\s\S+\sINFO\sexited:\sorchagent\s\(terminated\sby\sSIGABRT\s\(core\sdumped\);\snot\sexpected\)',
    'INFO\sswss#\/supervisord:\sorchagent\sterminate\scalled\safter\sthrowing\san\sinstance\sof',
    'mce:\s\[Hardware\sError\]:\sCPU\s\d:\sMachine\sCheck:\s0\sBank\s7:',
    'DEBUG\skernel:\s\[\S+\]\sEDAC\ssbridge\sMC\d:\sHANDLING\sMCE\sMEMORY\sERROR',
    'WARNING\skernel:\s\[\S+\]\sEDAC\sMC\d:\s\d+\sCE\smemory\sread\serror'
]
