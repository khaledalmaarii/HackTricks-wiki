# Ataques Físicos

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Recuperação de Senha da BIOS e Segurança do Sistema

**Redefinir a BIOS** pode ser feito de várias maneiras. A maioria das placas-mãe inclui uma **bateria** que, quando removida por cerca de **30 minutos**, redefinirá as configurações da BIOS, incluindo a senha. Alternativamente, um **jumper na placa-mãe** pode ser ajustado para redefinir essas configurações conectando pinos específicos.

Para situações em que ajustes de hardware não são possíveis ou práticos, **ferramentas de software** oferecem uma solução. Executar um sistema a partir de um **Live CD/USB** com distribuições como **Kali Linux** fornece acesso a ferramentas como **_killCmos_** e **_CmosPWD_**, que podem ajudar na recuperação da senha da BIOS.

Nos casos em que a senha da BIOS é desconhecida, inseri-la incorretamente **três vezes** geralmente resultará em um código de erro. Este código pode ser usado em sites como [https://bios-pw.org](https://bios-pw.org) para potencialmente recuperar uma senha utilizável.

### Segurança UEFI

Para sistemas modernos que utilizam **UEFI** em vez da BIOS tradicional, a ferramenta **chipsec** pode ser utilizada para analisar e modificar configurações UEFI, incluindo a desativação do **Secure Boot**. Isso pode ser realizado com o seguinte comando:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Análise de RAM e Ataques de Cold Boot

A RAM retém dados brevemente após a energia ser cortada, geralmente por **1 a 2 minutos**. Essa persistência pode ser estendida para **10 minutos** aplicando substâncias frias, como nitrogênio líquido. Durante esse período estendido, um **dump de memória** pode ser criado usando ferramentas como **dd.exe** e **volatility** para análise.

### Ataques de Acesso Direto à Memória (DMA)

**INCEPTION** é uma ferramenta projetada para **manipulação de memória física** através de DMA, compatível com interfaces como **FireWire** e **Thunderbolt**. Ela permite contornar procedimentos de login ao modificar a memória para aceitar qualquer senha. No entanto, é ineficaz contra sistemas **Windows 10**.

### Live CD/USB para Acesso ao Sistema

Alterar binários do sistema como **_sethc.exe_** ou **_Utilman.exe_** com uma cópia de **_cmd.exe_** pode fornecer um prompt de comando com privilégios de sistema. Ferramentas como **chntpw** podem ser usadas para editar o arquivo **SAM** de uma instalação do Windows, permitindo alterações de senha.

**Kon-Boot** é uma ferramenta que facilita o login em sistemas Windows sem conhecer a senha, modificando temporariamente o kernel do Windows ou UEFI. Mais informações podem ser encontradas em [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Lidando com Recursos de Segurança do Windows

#### Atalhos de Inicialização e Recuperação

- **Supr**: Acessar configurações da BIOS.
- **F8**: Entrar no modo de Recuperação.
- Pressionar **Shift** após a bandeira do Windows pode contornar o autologon.

#### Dispositivos BAD USB

Dispositivos como **Rubber Ducky** e **Teensyduino** servem como plataformas para criar dispositivos **bad USB**, capazes de executar cargas úteis predefinidas quando conectados a um computador alvo.

#### Cópia de Sombra de Volume

Privilégios de administrador permitem a criação de cópias de arquivos sensíveis, incluindo o arquivo **SAM**, através do PowerShell.

### Contornando a Criptografia BitLocker

A criptografia BitLocker pode potencialmente ser contornada se a **senha de recuperação** for encontrada dentro de um arquivo de dump de memória (**MEMORY.DMP**). Ferramentas como **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** podem ser utilizadas para esse fim.

### Engenharia Social para Adição de Chave de Recuperação

Uma nova chave de recuperação do BitLocker pode ser adicionada através de táticas de engenharia social, convencendo um usuário a executar um comando que adiciona uma nova chave de recuperação composta de zeros, simplificando assim o processo de descriptografia.

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
