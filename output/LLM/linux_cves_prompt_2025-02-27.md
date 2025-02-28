# Linux CVE Vulnerabilities Data

## Description
Vulnerabilities specifically affecting Linux systems from the past 360 days (as of 2025-02-27).

## Vulnerabilities Count
16 vulnerabilities found

## JSON Data for LLM Context
```json
[
  {
    "id": "CVE-2024-25693",
    "description": "There is a path traversal in Esri Portal for ArcGIS versions <= 11.2.  Successful exploitation may allow a remote, authenticated attacker to traverse the file system to access files or execute code outside of the intended directory. ",
    "score": 9.9,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "LOW",
    "user_interaction": "NONE",
    "cwe": "CWE-22",
    "affects_linux": true,
    "affects_windows": true,
    "likely_external_api": false
  },
  {
    "id": "CVE-2024-42256",
    "description": "In the Linux kernel, the following vulnerability has been resolved:\n\ncifs: Fix server re-repick on subrequest retry\n\nWhen a subrequest is marked for needing retry, netfs will call\ncifs_prepare_write() which will make cifs repick the server for the op\nbefore renegotiating credits; it then calls cifs_issue_write() which\ninvokes smb2_async_writev() - which re-repicks the server.\n\nIf a different server is then selected, this causes the increment of\nserver->in_flight to happen against one record and the decrement to happen\nagainst another, leading to misaccounting.\n\nFix this by just removing the repick code in smb2_async_writev().  As this\nis only called from netfslib-driven code, cifs_prepare_write() should\nalways have been called first, and so server should never be NULL and the\npreparatory step is repeated in the event that we do a retry.\n\nThe problem manifests as a warning looking something like:\n\n WARNING: CPU: 4 PID: 72896 at fs/smb/client/smb2ops.c:97 smb2_add_credits+0x3f0/0x9e0 [cifs]\n ...\n RIP: 0010:smb2_add_credits+0x3f0/0x9e0 [cifs]\n ...\n  smb2_writev_callback+0x334/0x560 [cifs]\n  cifs_demultiplex_thread+0x77a/0x11b0 [cifs]\n  kthread+0x187/0x1d0\n  ret_from_fork+0x34/0x60\n  ret_from_fork_asm+0x1a/0x30\n\nWhich may be triggered by a number of different xfstests running against an\nAzure server in multichannel mode.  generic/249 seems the most repeatable,\nbut generic/215, generic/249 and generic/308 may also show it.",
    "score": 9.8,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "NVD-CWE-noinfo",
    "affects_linux": true,
    "affects_windows": false,
    "likely_external_api": true
  },
  {
    "id": "CVE-2023-27584",
    "description": "Dragonfly is an open source P2P-based file distribution and image acceleration system. It is hosted by the Cloud Native Computing Foundation (CNCF) as an Incubating Level Project. Dragonfly uses JWT to verify user. However, the secret key for JWT, \"Secret Key\", is hard coded, which leads to authentication bypass. An attacker can perform any action as a user with admin privileges. This issue has been addressed in release version 2.0.9. All users are advised to upgrade. There are no known workarounds for this vulnerability.",
    "score": 9.8,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-321; CWE-798",
    "affects_linux": true,
    "affects_windows": false,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-9680",
    "description": "An attacker was able to achieve code execution in the content process by exploiting a use-after-free in Animation timelines. We have had reports of this vulnerability being exploited in the wild. This vulnerability affects Firefox < 131.0.2, Firefox ESR < 128.3.1, Firefox ESR < 115.16.1, Thunderbird < 131.0.1, Thunderbird < 128.3.1, and Thunderbird < 115.16.0.",
    "score": 9.8,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-416; CWE-416",
    "affects_linux": true,
    "affects_windows": false,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-43498",
    "description": ".NET and Visual Studio Remote Code Execution Vulnerability",
    "score": 9.8,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-843; NVD-CWE-noinfo",
    "affects_linux": true,
    "affects_windows": true,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-47606",
    "description": "GStreamer is a library for constructing graphs of media-handling components. An integer underflow has been detected in the function qtdemux_parse_theora_extension within qtdemux.c. The vulnerability occurs due to an underflow of the gint size variable, which causes size to hold a large unintended value when cast to an unsigned integer. This 32-bit negative value is then cast to a 64-bit unsigned integer (0xfffffffffffffffa) in a subsequent call to gst_buffer_new_and_alloc. The function gst_buffer_new_allocate then attempts to allocate memory, eventually calling _sysmem_new_block. The function _sysmem_new_block adds alignment and header size to the (unsigned) size, causing the overflow of the 'slice_size' variable. As a result, only 0x89 bytes are allocated, despite the large input size. When the following memcpy call occurs in gst_buffer_fill, the data from the input file will overwrite the content of the GstMapInfo info structure. Finally, during the call to gst_memory_unmap, the overwritten memory may cause a function pointer hijack, as the mem->allocator->mem_unmap_full function is called with a corrupted pointer. This function pointer overwrite could allow an attacker to alter the execution flow of the program, leading to arbitrary code execution. This vulnerability is fixed in 1.24.10.",
    "score": 9.8,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-190; CWE-191",
    "affects_linux": true,
    "affects_windows": false,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-2362",
    "description": "A path traversal vulnerability exists in the parisneo/lollms-webui version 9.3 on the Windows platform. Due to improper validation of file paths between Windows and Linux environments, an attacker can exploit this vulnerability to delete any file on the system. The issue arises from the lack of adequate sanitization of user-supplied input in the 'del_preset' endpoint, where the application fails to prevent the use of absolute paths or directory traversal sequences ('..'). As a result, an attacker can send a specially crafted request to the 'del_preset' endpoint to delete files outside of the intended directory.",
    "score": 9.1,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-36; CWE-22",
    "affects_linux": true,
    "affects_windows": true,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-37371",
    "description": "In MIT Kerberos 5 (aka krb5) before 1.21.3, an attacker can cause invalid memory reads during GSS message token handling by sending message tokens with invalid length fields.",
    "score": 9.1,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "NVD-CWE-Other",
    "affects_linux": true,
    "affects_windows": false,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-46958",
    "description": "In Nextcloud Desktop Client 3.13.1 through 3.13.3 on Linux, synchronized files (between the server and client) may become world writable or world readable. This is fixed in 3.13.4.",
    "score": 9.1,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "NVD-CWE-noinfo",
    "affects_linux": true,
    "affects_windows": false,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-49388",
    "description": "Sensitive information manipulation due to improper authorization. The following products are affected: Acronis Cyber Protect 16 (Linux, Windows) before build 38690.",
    "score": 9.1,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-639; CWE-639",
    "affects_linux": true,
    "affects_windows": true,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-47685",
    "description": "In the Linux kernel, the following vulnerability has been resolved:\n\nnetfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put()\n\nsyzbot reported that nf_reject_ip6_tcphdr_put() was possibly sending\ngarbage on the four reserved tcp bits (th->res1)\n\nUse skb_put_zero() to clear the whole TCP header,\nas done in nf_reject_ip_tcphdr_put()\n\nBUG: KMSAN: uninit-value in nf_reject_ip6_tcphdr_put+0x688/0x6c0 net/ipv6/netfilter/nf_reject_ipv6.c:255\n  nf_reject_ip6_tcphdr_put+0x688/0x6c0 net/ipv6/netfilter/nf_reject_ipv6.c:255\n  nf_send_reset6+0xd84/0x15b0 net/ipv6/netfilter/nf_reject_ipv6.c:344\n  nft_reject_inet_eval+0x3c1/0x880 net/netfilter/nft_reject_inet.c:48\n  expr_call_ops_eval net/netfilter/nf_tables_core.c:240 [inline]\n  nft_do_chain+0x438/0x22a0 net/netfilter/nf_tables_core.c:288\n  nft_do_chain_inet+0x41a/0x4f0 net/netfilter/nft_chain_filter.c:161\n  nf_hook_entry_hookfn include/linux/netfilter.h:154 [inline]\n  nf_hook_slow+0xf4/0x400 net/netfilter/core.c:626\n  nf_hook include/linux/netfilter.h:269 [inline]\n  NF_HOOK include/linux/netfilter.h:312 [inline]\n  ipv6_rcv+0x29b/0x390 net/ipv6/ip6_input.c:310\n  __netif_receive_skb_one_core net/core/dev.c:5661 [inline]\n  __netif_receive_skb+0x1da/0xa00 net/core/dev.c:5775\n  process_backlog+0x4ad/0xa50 net/core/dev.c:6108\n  __napi_poll+0xe7/0x980 net/core/dev.c:6772\n  napi_poll net/core/dev.c:6841 [inline]\n  net_rx_action+0xa5a/0x19b0 net/core/dev.c:6963\n  handle_softirqs+0x1ce/0x800 kernel/softirq.c:554\n  __do_softirq+0x14/0x1a kernel/softirq.c:588\n  do_softirq+0x9a/0x100 kernel/softirq.c:455\n  __local_bh_enable_ip+0x9f/0xb0 kernel/softirq.c:382\n  local_bh_enable include/linux/bottom_half.h:33 [inline]\n  rcu_read_unlock_bh include/linux/rcupdate.h:908 [inline]\n  __dev_queue_xmit+0x2692/0x5610 net/core/dev.c:4450\n  dev_queue_xmit include/linux/netdevice.h:3105 [inline]\n  neigh_resolve_output+0x9ca/0xae0 net/core/neighbour.c:1565\n  neigh_output include/net/neighbour.h:542 [inline]\n  ip6_finish_output2+0x2347/0x2ba0 net/ipv6/ip6_output.c:141\n  __ip6_finish_output net/ipv6/ip6_output.c:215 [inline]\n  ip6_finish_output+0xbb8/0x14b0 net/ipv6/ip6_output.c:226\n  NF_HOOK_COND include/linux/netfilter.h:303 [inline]\n  ip6_output+0x356/0x620 net/ipv6/ip6_output.c:247\n  dst_output include/net/dst.h:450 [inline]\n  NF_HOOK include/linux/netfilter.h:314 [inline]\n  ip6_xmit+0x1ba6/0x25d0 net/ipv6/ip6_output.c:366\n  inet6_csk_xmit+0x442/0x530 net/ipv6/inet6_connection_sock.c:135\n  __tcp_transmit_skb+0x3b07/0x4880 net/ipv4/tcp_output.c:1466\n  tcp_transmit_skb net/ipv4/tcp_output.c:1484 [inline]\n  tcp_connect+0x35b6/0x7130 net/ipv4/tcp_output.c:4143\n  tcp_v6_connect+0x1bcc/0x1e40 net/ipv6/tcp_ipv6.c:333\n  __inet_stream_connect+0x2ef/0x1730 net/ipv4/af_inet.c:679\n  inet_stream_connect+0x6a/0xd0 net/ipv4/af_inet.c:750\n  __sys_connect_file net/socket.c:2061 [inline]\n  __sys_connect+0x606/0x690 net/socket.c:2078\n  __do_sys_connect net/socket.c:2088 [inline]\n  __se_sys_connect net/socket.c:2085 [inline]\n  __x64_sys_connect+0x91/0xe0 net/socket.c:2085\n  x64_sys_call+0x27a5/0x3ba0 arch/x86/include/generated/asm/syscalls_64.h:43\n  do_syscall_x64 arch/x86/entry/common.c:52 [inline]\n  do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83\n entry_SYSCALL_64_after_hwframe+0x77/0x7f\n\nUninit was stored to memory at:\n  nf_reject_ip6_tcphdr_put+0x60c/0x6c0 net/ipv6/netfilter/nf_reject_ipv6.c:249\n  nf_send_reset6+0xd84/0x15b0 net/ipv6/netfilter/nf_reject_ipv6.c:344\n  nft_reject_inet_eval+0x3c1/0x880 net/netfilter/nft_reject_inet.c:48\n  expr_call_ops_eval net/netfilter/nf_tables_core.c:240 [inline]\n  nft_do_chain+0x438/0x22a0 net/netfilter/nf_tables_core.c:288\n  nft_do_chain_inet+0x41a/0x4f0 net/netfilter/nft_chain_filter.c:161\n  nf_hook_entry_hookfn include/linux/netfilter.h:154 [inline]\n  nf_hook_slow+0xf4/0x400 net/netfilter/core.c:626\n  nf_hook include/linux/netfilter.h:269 [inline]\n  NF_HOOK include/linux/netfilter.h:312 [inline]\n  ipv6_rcv+0x29b/0x390 net/ipv6/ip6_input.c:310\n  __netif_receive_skb_one_core\n---truncated---",
    "score": 9.1,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-908",
    "affects_linux": true,
    "affects_windows": false,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-1222",
    "description": "This allows attackers to use a maliciously formed API request to gain access to an API authorization level with elevated privileges. This applies to a small subset of PaperCut NG/MF API calls.",
    "score": 8.6,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-250; NVD-CWE-Other",
    "affects_linux": true,
    "affects_windows": true,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-5828",
    "description": "Expression Language Injection vulnerability in Hitachi Tuning Manager on Windows, Linux, Solaris allows Code Injection.This issue affects Hitachi Tuning Manager: before 8.8.7-00.",
    "score": 8.6,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-917; CWE-917",
    "affects_linux": true,
    "affects_windows": true,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-2223",
    "description": "An Incorrect Regular Expression vulnerability in Bitdefender GravityZone Update Server allows an attacker to cause a Server Side Request Forgery and reconfigure the relay. This issue affects the following products that include the vulnerable component: \n\nBitdefender Endpoint Security for Linux version 7.0.5.200089\nBitdefender Endpoint Security for  Windows version 7.9.9.380\nGravityZone Control Center (On Premises) version 6.36.1\n",
    "score": 8.1,
    "attack_vector": "NETWORK",
    "attack_complexity": "HIGH",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-185; CWE-697",
    "affects_linux": true,
    "affects_windows": true,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-2224",
    "description": "Improper Limitation of a Pathname to a Restricted Directory (‘Path Traversal’) vulnerability in the UpdateServer component of Bitdefender GravityZone allows an attacker to execute arbitrary code on vulnerable instances. This issue affects the following products that include the vulnerable component: \n\nBitdefender Endpoint Security for Linux version 7.0.5.200089\nBitdefender Endpoint Security for  Windows version 7.9.9.380\nGravityZone Control Center (On Premises) version 6.36.1\n",
    "score": 8.1,
    "attack_vector": "NETWORK",
    "attack_complexity": "HIGH",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-22",
    "affects_linux": true,
    "affects_windows": true,
    "likely_external_api": true
  },
  {
    "id": "CVE-2024-39747",
    "description": "IBM Sterling Connect:Direct Web Services 6.0, 6.1, 6.2, and 6.3 uses default credentials for potentially critical functionality.",
    "score": 8.1,
    "attack_vector": "NETWORK",
    "attack_complexity": "HIGH",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe": "CWE-1392",
    "affects_linux": true,
    "affects_windows": true,
    "likely_external_api": true
  }
]
```



## Example Prompt:
```
Analyze these vulnerability details and identify patterns, trends, or notable security concerns:

[Insert the JSON data above here]

Based on this data, what are the most significant security risks and what mitigation strategies would you recommend?
```
