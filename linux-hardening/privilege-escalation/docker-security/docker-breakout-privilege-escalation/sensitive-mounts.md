<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>


Wystawienie `/proc` i `/sys` bez odpowiedniej izolacji przestrzeni nazw niesie ze sobą znaczne ryzyko bezpieczeństwa, w tym zwiększenie powierzchni ataku i ujawnienie informacji. Te katalogi zawierają wrażliwe pliki, które w przypadku niewłaściwej konfiguracji lub dostępu przez nieuprawnionego użytkownika mogą prowadzić do ucieczki z kontenera, modyfikacji hosta lub dostarczenia informacji ułatwiających dalsze ataki. Na przykład, nieprawidłowe zamontowanie `-v /proc:/host/proc` może obejść ochronę AppArmor ze względu na jej opartą na ścieżce naturę, pozostawiając `/host/proc` bez ochrony.

**Możesz znaleźć dalsze szczegóły dotyczące każdej potencjalnej podatności na stronie [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts).**

# Podatności procfs

## `/proc/sys`
Ten katalog umożliwia dostęp do modyfikacji zmiennych jądra, zwykle za pomocą `sysctl(2)`, i zawiera kilka podkatalogów, które budzą obawy:

### **`/proc/sys/kernel/core_pattern`**
- Opisany w [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Pozwala zdefiniować program do wykonania przy generowaniu pliku rdzenia, gdzie pierwsze 128 bajtów stanowi argumenty. Może to prowadzić do wykonania kodu, jeśli plik zaczyna się od rury `|`.
- **Przykład testowania i eksploatacji**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Sprawdź dostęp do zapisu
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Ustaw niestandardowy obsługiwacz
sleep 5 && ./crash & # Wywołaj obsługiwacz
```

### **`/proc/sys/kernel/modprobe`**
- Szczegółowo opisany w [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Zawiera ścieżkę do ładowacza modułów jądra, wywoływanego do ładowania modułów jądra.
- **Przykład sprawdzania dostępu**:
```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Sprawdź dostęp do modprobe
```

### **`/proc/sys/vm/panic_on_oom`**
- Wzmiankowany w [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Globalna flaga kontrolująca, czy jądro wpada w panikę czy wywołuje OOM killer, gdy wystąpi warunek OOM.

### **`/proc/sys/fs`**
- Zgodnie z [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), zawiera opcje i informacje dotyczące systemu plików.
- Dostęp do zapisu może umożliwić różne ataki typu odmowa usługi przeciwko hostowi.

### **`/proc/sys/fs/binfmt_misc`**
- Umożliwia rejestrację interpreterów dla formatów binarnych niezgodnych z natywnym na podstawie ich magicznej liczby.
- Może prowadzić do eskalacji uprawnień lub dostępu do powłoki roota, jeśli `/proc/sys/fs/binfmt_misc/register` jest zapisywalny.
- Odpowiedni exploit i wyjaśnienie:
- [Rootkit dla biednych za pomocą binfmt_misc](https://github.com/toffan/binfmt_misc)
- Szczegółowy samouczek: [Link do wideo](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## Inne w `/proc`

### **`/proc/config.gz`**
- Może ujawnić konfigurację jądra, jeśli `CONFIG_IKCONFIG_PROC` jest włączone.
- Przydatne dla atakujących do identyfikacji podatności w działającym jądrze.

### **`/proc/sysrq-trigger`**
- Umożliwia wywoływanie poleceń Sysrq, potencjalnie powodując natychmiastowe ponowne uruchomienie systemu lub inne krytyczne działania.
- **Przykład ponownego uruchamiania hosta**:
```bash
echo b > /proc/sysrq-trigger # Ponowne uruchomienie hosta
```

### **`/proc/kmsg`**
- Ujawnia komunikaty z bufora pierścieniowego jądra.
- Może pomóc w atakach na jądro, wyciekach adresów i dostarczaniu wrażliwych informacji systemowych.

### **`/proc/kallsyms`**
- Wyświetla eksportowane symbole jądra i ich adresy.
- Niezbędne do rozwoju exploitów jądra, zwłaszcza do pokonania KASLR.
- Informacje o adresie są ograniczone, gdy `kptr_restrict` jest ustawione na `1` lub `2`.
- Szczegóły w [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/[pid]/mem`**
- Interfejsuje się z urządzeniem pamięci jądra `/dev/mem`.
- Historycznie podatny na ataki eskalacji uprawnień.
- Więcej informacji na temat [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/kcore`**
- Reprezentuje fizyczną pamięć systemu w formacie ELF core.
- Odczyt może ujawniać zawartość pamięci hosta i innych kontenerów.
- Duży rozmiar pliku może prowadzić do problemów z odczytem lub awarii oprogramowania.
- Szczegółowe informacje na temat użycia w [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

### **`/proc/kmem`**
- Alternatywny interfejs dla `/dev/kmem`, reprezentujący wirtualną pamięć jądra.
- Umożliwia odczyt i zapis, a więc bezpośrednią modyfikację pamięci jądra.

### **`/proc/mem`**
- Alternatywny interfejs dla `/dev/mem`, reprezentujący pamięć fizyczną.
- Umożliwia odczyt i zapis, modyfikacja całej pamięci wymaga przeliczenia adresów wirtualnych na fizyczne.

### **`/proc/sched_debug`**
- Zwraca informacje o harmonogramowaniu procesów, omijając ochrony przestrzeni nazw PID.
- Ujawnia nazwy procesów, identyfikatory i identyfikatory grupy kontrolnej.

### **`/proc/[pid]/mountinfo`**
- Udostępnia informacje o punktach montowania w przestrzeni nazw montowania procesu.
- Ujawnia lokalizację `rootfs` lub obrazu kontenera.

# Podatności w `/sys`

### **`/sys/kernel/ue
### **`/sys/class/thermal`**
- Kontroluje ustawienia temperatury, potencjalnie powodując ataki typu DoS lub fizyczne uszkodzenia.

### **`/sys/kernel/vmcoreinfo`**
- Wycieka adresy jądra, potencjalnie kompromitując KASLR.

### **`/sys/kernel/security`**
- Zawiera interfejs `securityfs`, umożliwiający konfigurację modułów zabezpieczeń Linuxa, takich jak AppArmor.
- Dostęp może umożliwić kontenerowi wyłączenie systemu MAC.

### **`/sys/firmware/efi/vars` i `/sys/firmware/efi/efivars`**
- Udostępnia interfejsy do interakcji z zmiennymi EFI w NVRAM.
- Niewłaściwa konfiguracja lub wykorzystanie może spowodować zablokowanie laptopów lub niemożność uruchomienia hosta.

### **`/sys/kernel/debug`**
- `debugfs` oferuje interfejs do debugowania jądra bez żadnych ograniczeń.
- Historia problemów związanych z bezpieczeństwem związana z jego nieograniczoną naturą.


## References
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
