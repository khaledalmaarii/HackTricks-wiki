# Ataques Físicos

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

## Senha do BIOS

### A bateria

A maioria das **placas-mãe** possui uma **bateria**. Se você **removê-la** por **30min**, as configurações do BIOS serão **reiniciadas** (senha inclusa).

### Jumper CMOS

A maioria das **placas-mãe** possui um **jumper** que pode reiniciar as configurações. Este jumper conecta um pino central com outro, se você **conectar esses pinos, a placa-mãe será reiniciada**.

### Ferramentas ao Vivo

Se você puder **executar**, por exemplo, um Linux **Kali** de um CD/USB ao vivo, você poderia usar ferramentas como _**killCmos**_ ou _**CmosPWD**_ (este último está incluído no Kali) para tentar **recuperar a senha do BIOS**.

### Recuperação de senha do BIOS online

Digite a senha do BIOS **3 vezes errada**, então o BIOS mostrará uma **mensagem de erro** e será bloqueado.\
Visite a página [https://bios-pw.org](https://bios-pw.org) e **introduza o código de erro** mostrado pelo BIOS e você pode ter sorte e obter uma **senha válida** (a **mesma busca pode mostrar diferentes senhas e mais de uma pode ser válida**).

## UEFI

Para verificar as configurações do UEFI e realizar algum tipo de ataque, você deve tentar [chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf).\
Usando esta ferramenta, você poderia facilmente desativar o Secure Boot:
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### Cold boot

A **memória RAM é persistente de 1 a 2 minutos** a partir do momento em que o computador é desligado. Se você aplicar **frio** (nitrogênio líquido, por exemplo) no cartão de memória, pode estender esse tempo para até **10 minutos**.

Então, você pode fazer um **dump de memória** (usando ferramentas como dd.exe, mdd.exe, Memoryze, win32dd.exe ou DumpIt) para analisar a memória.

Você deve **analisar** a memória **usando volatility**.

### [INCEPTION](https://github.com/carmaa/inception)

Inception é uma ferramenta de **manipulação de memória física** e hacking que explora DMA baseado em PCI. A ferramenta pode atacar através de **FireWire**, **Thunderbolt**, **ExpressCard**, PC Card e qualquer outra interface HW PCI/PCIe.\
**Conecte** seu computador ao computador da vítima através de uma dessas **interfaces** e o **INCEPTION** tentará **patchear** a **memória física** para lhe dar **acesso**.

**Se o INCEPTION for bem-sucedido, qualquer senha introduzida será válida.**

**Não funciona com Windows10.**

## Live CD/USB

### Sticky Keys e mais

* **SETHC:** _sethc.exe_ é invocado quando SHIFT é pressionado 5 vezes
* **UTILMAN:** _Utilman.exe_ é invocado ao pressionar WINDOWS+U
* **OSK:** _osk.exe_ é invocado ao pressionar WINDOWS+U e, em seguida, iniciar o teclado na tela
* **DISP:** _DisplaySwitch.exe_ é invocado ao pressionar WINDOWS+P

Esses binários estão localizados dentro de _**C:\Windows\System32**_. Você pode **alterar** qualquer um deles por uma **cópia** do binário **cmd.exe** (também na mesma pasta) e toda vez que você invocar qualquer um desses binários, um prompt de comando como **SYSTEM** aparecerá.

### Modificando SAM

Você pode usar a ferramenta _**chntpw**_ para **modificar o arquivo** _**SAM**_ de um sistema de arquivos Windows montado. Então, você poderia mudar a senha do usuário Administrador, por exemplo.\
Esta ferramenta está disponível no KALI.
```
chntpw -h
chntpw -l <path_to_SAM>
```
**Dentro de um sistema Linux, você poderia modificar o arquivo** _**/etc/shadow**_ **ou** _**/etc/passwd**_.

### **Kon-Boot**

**Kon-Boot** é uma das melhores ferramentas disponíveis que permite fazer login no Windows sem conhecer a senha. Funciona **interceptando o BIOS do sistema e alterando temporariamente o conteúdo do kernel do Windows** durante a inicialização (novas versões também funcionam com **UEFI**). Em seguida, permite que você insira **qualquer coisa como senha** durante o login. Na próxima vez que você iniciar o computador sem o Kon-Boot, a senha original estará de volta, as alterações temporárias serão descartadas e o sistema se comportará como se nada tivesse acontecido.\
Leia Mais: [https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

É um CD/USB live que pode **patchear a memória** para que você **não precise conhecer a senha para fazer login**.\
O Kon-Boot também realiza o truque **StickyKeys** para que você possa pressionar _**Shift**_ **5 vezes para obter um cmd de Administrador**.

## **Executando Windows**

### Atalhos iniciais

### Atalhos de inicialização

* supr - BIOS
* f8 - Modo de recuperação
* _supr_ - BIOS ini
* _f8_ - Modo de recuperação
* _Shift_ (após o banner do windows) - Ir para a página de login em vez de autologon (evitar autologon)

### **BAD USBs**

#### **Tutoriais Rubber Ducky**

* [Tutorial 1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [Tutorial 2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [Payloads e tutoriais](https://github.com/Screetsec/Pateensy)

Há também toneladas de tutoriais sobre **como criar seu próprio bad USB**.

### Cópia de Sombra de Volume

Com privilégios de administrador e powershell, você poderia fazer uma cópia do arquivo SAM.[ Veja este código](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy).

## Bypassing Bitlocker

O Bitlocker usa **2 senhas**. A usada pelo **usuário** e a senha de **recuperação** (48 dígitos).

Se você tiver sorte e dentro da sessão atual do Windows existir o arquivo _**C:\Windows\MEMORY.DMP**_ (é um dump de memória), você poderia tentar **procurar dentro dele a senha de recuperação**. Você pode **obter este arquivo** e uma **cópia do sistema de arquivos** e então usar _Elcomsoft Forensic Disk Decryptor_ para obter o conteúdo (isso só funcionará se a senha estiver dentro do dump de memória). Você também poderia **forçar o dump de memória** usando _**NotMyFault**_ da _Sysinternals_, mas isso reiniciará o sistema e deve ser executado como Administrador.

Você também poderia tentar um **ataque de força bruta** usando _**Passware Kit Forensic**_.

### Engenharia Social

Por fim, você poderia fazer o usuário adicionar uma nova senha de recuperação fazendo-o executar como administrador:
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
Isso adicionará uma nova chave de recuperação (composta por 48 zeros) no próximo login.

Para verificar as chaves de recuperação válidas, você pode executar:
```
manage-bde -protectors -get c:
```
<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo do** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo do [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
