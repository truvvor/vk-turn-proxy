## Inventory (us.overheat.cn, 2026-05-10T14:24:23Z)

### Runner user
```
uid=1000(runner) gid=1000(runner) groups=1000(runner)
Runner.Listener pid:  1415124
```
### Listening UDP sockets
```
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
UNCONN 0      0         127.0.0.54:53         0.0.0.0:*          
UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*          
UNCONN 0      0                  *:57784            *:*          
UNCONN 0      0                  *:59959            *:*          
UNCONN 0      0                  *:60058            *:*          
UNCONN 0      0                  *:43714            *:*          
UNCONN 0      0                  *:54083            *:*          
UNCONN 0      0                  *:39864            *:*          
UNCONN 0      0                  *:44029            *:*          
UNCONN 0      0                  *:48128            *:*          
UNCONN 0      0                  *:36522            *:*          
UNCONN 0      0                  *:55024            *:*          
UNCONN 0      0                  *:44802            *:*          
UNCONN 0      0                  *:46879            *:*          
UNCONN 0      0                  *:53064            *:*          
UNCONN 0      0                  *:47216            *:*          
```
### Listening TCP sockets (top 30)
```
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*          
LISTEN 6      5            0.0.0.0:8888       0.0.0.0:*          
LISTEN 0      4096       127.0.0.1:20242      0.0.0.0:*          
LISTEN 0      4096       127.0.0.1:20241      0.0.0.0:*          
LISTEN 6      5            0.0.0.0:9443       0.0.0.0:*          
LISTEN 0      4096      127.0.0.54:53         0.0.0.0:*          
LISTEN 6      5            0.0.0.0:8080       0.0.0.0:*          
LISTEN 0      1024       127.0.0.1:40000      0.0.0.0:*          
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
LISTEN 0      4096       127.0.0.1:62789      0.0.0.0:*          
LISTEN 0      4096               *:443              *:*          
LISTEN 0      4096            [::]:22            [::]:*          
LISTEN 0      4096               *:8443             *:*          
LISTEN 0      4096               *:64300            *:*          
LISTEN 0      4096               *:20443            *:*          
```
### WireGuard
/etc/wireguard not readable (or missing) without sudo.
wg show (may need sudo):
```
```
WireGuard interfaces (ip link):
```
```
### Xray
/etc/xray contents:
```
total 20
drwxr-xr-x   2 root root  4096 Apr 17 18:28 .
drwxr-xr-x 115 root root 12288 May  9 06:16 ..
-rw-r--r--   1 root root  1572 Apr 17 18:31 config.json
```
systemctl status xray:
```
Unit xray.service could not be found.
```
### vk-turn-proxy (existing install, if any)
```
ls: cannot access '/opt/vk-turn-proxy/': No such file or directory
ls: cannot access '/etc/vk-turn-proxy/': No such file or directory
```
### Public IP
```
77.90.8.199
```
### Sudo capabilities (sudo -n -l)
```
Matching Defaults entries for runner on us:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User runner may run the following commands on us:
    (ALL) NOPASSWD: ALL
```
### Sudo: read WireGuard ListenPort
```
grep: /etc/wireguard/*.conf: No such file or directory
```
### Sudo: wg show
```
```
### bootstrap.sh --dry-run (via sudo -n)
```
------------------------------------------------------------
Inventory
------------------------------------------------------------
WireGuard:    NOT detected
Xray:         active=no, port 20443  (source: /etc/xray/config.json (jq))
vk-turn-proxy will LISTEN on UDP 56000  (free, won't collide)
Runner user:  runner  (pid 1415124)
Public IP:    77.90.8.199
------------------------------------------------------------
Plan
------------------------------------------------------------
  install.sh will create:
    /etc/vk-turn-proxy/udp.env    LISTEN=0.0.0.0:56000  CONNECT=127.0.0.1:51820
    /etc/vk-turn-proxy/vless.env  LISTEN=0.0.0.0:56001  CONNECT=127.0.0.1:20443
  systemctl will:
    daemon-reload, enable vk-turn-proxy@udp.service, enable vk-turn-proxy@vless.service
  sudoers will be installed at /etc/sudoers.d/vk-turn-proxy-runner for user 'runner'
  Existing wireguard / xray configurations will NOT be touched.

  Connection URL after deploy:  77.90.8.199:56000/udp
------------------------------------------------------------
Dry-run: nothing changed.
------------------------------------------------------------

(bootstrap.sh --dry-run exit: 0)
```
