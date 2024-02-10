<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite videti **oglašavanje vaše kompanije na HackTricks-u** ili **preuzeti HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>


Izlaganje `/proc` i `/sys` bez odgovarajuće izolacije imenika predstavlja značajne sigurnosne rizike, uključujući povećanje površine napada i otkrivanje informacija. Ovi direktorijumi sadrže osetljive datoteke koje, ako su netačno konfigurisane ili pristupljene od strane neovlašćenog korisnika, mogu dovesti do bekstva iz kontejnera, izmena na hostu ili pružanja informacija koje pomažu daljim napadima. Na primer, netačno montiranje `-v /proc:/host/proc` može zaobići AppArmor zaštitu zbog svoje putem zasnovane prirode, ostavljajući `/host/proc` nezaštićenim.

**Možete pronaći dalje detalje o svakom potencijalnom propustu na [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts).**

# procfs Ranjivosti

## `/proc/sys`
Ovaj direktorijum omogućava pristup za izmenu kernel promenljivih, obično putem `sysctl(2)`, i sadrži nekoliko poddirektorijuma od interesa:

### **`/proc/sys/kernel/core_pattern`**
- Opisano u [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Omogućava definisanje programa koji se izvršava prilikom generisanja core fajla sa prvih 128 bajtova kao argumentima. Ovo može dovesti do izvršavanja koda ako fajl počinje sa cevkom `|`.
- **Testiranje i primer eksploatacije**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Testiranje pristupa pisanju
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Postavljanje prilagođenog rukovaoca
sleep 5 && ./crash & # Pokretanje rukovaoca
```

### **`/proc/sys/kernel/modprobe`**
- Detaljno opisano u [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Sadrži putanju do učitavača kernel modula, koji se poziva prilikom učitavanja kernel modula.
- **Provera pristupa primer**:
```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Provera pristupa modprobe-u
```

### **`/proc/sys/vm/panic_on_oom`**
- Pomenuto u [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Globalna oznaka koja kontroliše da li kernel pravi paniku ili pokreće OOM ubica kada se pojavi OOM uslov.

### **`/proc/sys/fs`**
- Kako je navedeno u [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), sadrži opcije i informacije o fajl sistemu.
- Pristup pisanju može omogućiti razne napade uskraćivanjem usluge na hostu.

### **`/proc/sys/fs/binfmt_misc`**
- Omogućava registraciju interpretatora za ne-nativne binarne formate na osnovu njihovog magičnog broja.
- Može dovesti do eskalacije privilegija ili pristupa root shell-u ako je `/proc/sys/fs/binfmt_misc/register` dostupan za pisanje.
- Relevantni eksploit i objašnjenje:
- [Rootkit za siromašne putem binfmt_misc](https://github.com/toffan/binfmt_misc)
- Detaljan tutorijal: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## Ostali u `/proc`

### **`/proc/config.gz`**
- Može otkriti konfiguraciju kernela ako je `CONFIG_IKCONFIG_PROC` omogućeno.
- Korisno napadačima za identifikaciju ranjivosti u pokrenutom kernelu.

### **`/proc/sysrq-trigger`**
- Omogućava pozivanje Sysrq komandi, što može dovesti do trenutnog ponovnog pokretanja sistema ili drugih kritičnih radnji.
- **Primer ponovnog pokretanja hosta**:
```bash
echo b > /proc/sysrq-trigger # Ponovno pokretanje hosta
```

### **`/proc/kmsg`**
- Otkriva poruke iz prstena za kernel.
- Može pomoći u eksploataciji kernela, otkrivanju adresa i pružanju osetljivih informacija o sistemu.

### **`/proc/kallsyms`**
- Navodi izvođene simbole kernela i njihove adrese.
- Neophodno za razvoj eksploita kernela, posebno za prevazilaženje KASLR-a.
- Informacije o adresi su ograničene kada je `kptr_restrict` postavljen na `1` ili `2`.
- Detalji u [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/[pid]/mem`**
- Interfejs sa uređajem za memoriju kernela `/dev/mem`.
- Istoriski ranjiv na napade eskalacije privilegija.
- Više informacija na [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/kcore`**
- Predstavlja fizičku memoriju sistema u ELF core formatu.
- Čitanje može otkriti sadržaj memorije host sistema i drugih kontejnera.
- Velika veličina fajla može dovesti do problema sa čitanjem ili rušenjem softvera.
- Detaljno objašnjenje u [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

### **`/proc/kmem`**
- Alternativni interfejs za `/dev/kmem`, predstavlja virtuelnu memoriju kernela.
- Omogućava čitanje i pisanje, što direktno menja memoriju kernela.

### **`/proc/mem`**
- Alternativni interfejs za `/dev/mem`, predstavlja fizičku memoriju.
- Omogućava čitanje i pisanje, a za modifikaciju cele memorije potrebno je rešiti virtuelne u fizičke adrese.

### **`/proc/sched_debug`**
- Vraća informacije o rasporedu procesa, zaobilazeći zaštitu PID imenskog prostora.
- Otkriva imena procesa, ID-ove i identifikatore cgroup-a.

### **`/proc/[pid]/mountinfo`**
- Pruža informacije o tačkama montiranja u imenskom prostoru procesa.
- Otkriva lokaciju `rootfs`-a ili slike kontejnera.

## `/sys` Ranjivosti

### **`/sys/kernel/uevent_helper`**
- Koristi se za rukovanje `uevent`-ima kernel uređaja.
- Pisanje u `/sys/kernel/uevent_helper` može izvršiti proizvoljne skripte prilikom okidača `uevent`.
- **Primer eksplo
### **`/sys/class/thermal`**
- Kontroliše podešavanja temperature, potencijalno uzrokujući DoS napade ili fizičku štetu.

### **`/sys/kernel/vmcoreinfo`**
- Otkriva adrese jezgra, potencijalno kompromitujući KASLR.

### **`/sys/kernel/security`**
- Sadrži `securityfs` interfejs, omogućavajući konfiguraciju Linux Security Modula kao što je AppArmor.
- Pristup može omogućiti kontejneru da onemogući svoj MAC sistem.

### **`/sys/firmware/efi/vars` i `/sys/firmware/efi/efivars`**
- Otkriva interfejse za interakciju sa EFI varijablama u NVRAM-u.
- Pogrešna konfiguracija ili iskorišćavanje može dovesti do oštećenja laptopa ili host mašine koja se ne može podići.

### **`/sys/kernel/debug`**
- `debugfs` nudi "bez pravila" interfejs za debagovanje jezgra.
- Ima istoriju sigurnosnih problema zbog svoje neograničene prirode.


## Reference
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Razumevanje i ojačavanje Linux kontejnera](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Zloupotreba privilegovanih i neprivilegovanih Linux kontejnera](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Pogledajte [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
