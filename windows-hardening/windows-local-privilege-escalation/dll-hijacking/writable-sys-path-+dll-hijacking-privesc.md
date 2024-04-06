# Writable Sys Path +Dll Hijacking Privesc

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Wprowadzenie

Jeśli odkryłeś, że możesz **pisać w folderze System Path** (zauważ, że to nie zadziała, jeśli możesz pisać w folderze User Path), istnieje możliwość, że możesz **podnieść uprawnienia** w systemie.

Aby to zrobić, możesz wykorzystać **Hijacking Dll**, gdzie przejmujesz bibliotekę, która jest ładowana przez usługę lub proces z **większymi uprawnieniami** niż twoje, a ponieważ ta usługa ładowana jest Dll, który prawdopodobnie nie istnieje w całym systemie, zostanie ona próbować go załadować z System Path, w którym możesz pisać.

Aby uzyskać więcej informacji na temat **czym jest Hijacking Dll**, sprawdź:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Podwyższanie uprawnień za pomocą Hijacking Dll

### Wyszukiwanie brakującego Dll

Pierwszą rzeczą, którą musisz zrobić, to **zidentyfikować proces**, który działa z **większymi uprawnieniami** niż ty i próbuje **załadować Dll z System Path**, w którym możesz pisać.

Problem w tych przypadkach polega na tym, że prawdopodobnie te procesy już działają. Aby dowiedzieć się, które Dll są brakujące dla usług, musisz uruchomić procmon tak szybko, jak to możliwe (przed załadowaniem procesów). Więc, aby znaleźć brakujące .dll, wykonaj:

* **Utwórz** folder `C:\privesc_hijacking` i dodaj ścieżkę `C:\privesc_hijacking` do **zmiennej środowiskowej System Path**. Możesz to zrobić **ręcznie** lub za pomocą **PS**:

```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```

* Uruchom **`procmon`** i przejdź do **`Opcje`** --> **`Włącz logowanie rozruchu`** i kliknij **`OK`** w okienku dialogowym.
* Następnie **zrestartuj** komputer. Po ponownym uruchomieniu **`procmon`** rozpocznie **rejestrację** zdarzeń.
* Gdy system **Windows** zostanie uruchomiony, uruchom ponownie **`procmon`**. Program poinformuje Cię, że działał i zapyta, czy chcesz zapisać zdarzenia w pliku. Odpowiedz **tak** i **zapisz zdarzenia w pliku**.
* **Po** wygenerowaniu **pliku**, **zamknij** otwarte okno **`procmon`** i **otwórz plik zdarzeń**.
* Dodaj te **filtry**, a znajdziesz wszystkie biblioteki DLL, które próbowały załadować się z zapisywalnego folderu System Path:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Brakujące biblioteki DLL

Uruchamiając to na darmowej **wirtualnej maszynie (vmware) z systemem Windows 11**, otrzymałem następujące wyniki:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

W tym przypadku pliki .exe są bezużyteczne, więc je zignoruj. Brakujące biblioteki DLL pochodziły z:

| Usługa                               | DLL                | Wiersz polecenia                                                     |
| ------------------------------------ | ------------------ | -------------------------------------------------------------------- |
| Harmonogram zadań (Schedule)         | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Usługa polityki diagnostycznej (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                                  | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Po znalezieniu tego, natknąłem się na interesujący post na blogu, który również wyjaśnia, jak [**wykorzystać WptsExtensions.dll do eskalacji uprawnień**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). To właśnie **teraz zamierzamy zrobić**.

### Wykorzystanie

Aby **przywileje** zostały **podniesione**, przechwycimy bibliotekę **WptsExtensions.dll**. Mając **ścieżkę** i **nazwę**, musimy tylko **wygenerować złośliwą bibliotekę DLL**.

Możesz [**spróbować użyć jednego z tych przykładów**](./#creating-and-compiling-dlls). Możesz uruchomić payloady takie jak: zdobądź powłokę rev, dodaj użytkownika, wykonaj beacon...

{% hint style="warning" %}
Zauważ, że **nie wszystkie usługi są uruchamiane** z kontem **`NT AUTHORITY\SYSTEM`**, niektóre są również uruchamiane z kontem **`NT AUTHORITY\LOCAL SERVICE`**, które ma **mniej uprawnień**, i nie będziesz w stanie utworzyć nowego użytkownika, wykorzystując jego uprawnienia.\
Jednak ten użytkownik ma uprawnienie **`seImpersonate`**, więc możesz użyć [**pakietu potato do eskalacji uprawnień**](../roguepotato-and-printspoofer.md). W tym przypadku powłoka rev jest lepszą opcją niż próba utworzenia użytkownika.
{% endhint %}

W chwili pisania tego artykułu usługa **Harmonogram zadań** jest uruchamiana z kontem **Nt AUTHORITY\SYSTEM**.

Po **wygenerowaniu złośliwej biblioteki DLL** (_w moim przypadku użyłem powłoki rev x64 i otrzymałem powłokę zwrotną, ale defender ją zabił, ponieważ pochodziła z msfvenom_), zapisz ją w zapisywalnym folderze System Path pod nazwą **WptsExtensions.dll** i **zrestartuj** komputer (lub zrestartuj usługę lub wykonaj inne czynności, aby ponownie uruchomić dotkniętą usługę/program).

Po ponownym uruchomieniu usługi, biblioteka DLL powinna zostać załadowana i wykonana (możesz **ponownie użyć** triku z **procmonem**, aby sprawdzić, czy biblioteka została załadowana zgodnie z oczekiwaniami).

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **na GitHubie**.

</details>
