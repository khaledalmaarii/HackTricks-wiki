# Ataques Físicos

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares roubadores**.

O principal objetivo do WhiteIntel é combater tomadas de conta e ataques de ransomware resultantes de malwares que roubam informações.

Você pode verificar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

---

## Recuperação de Senha do BIOS e Segurança do Sistema

**Redefinir o BIOS** pode ser feito de várias maneiras. A maioria das placas-mãe inclui uma **bateria** que, quando removida por cerca de **30 minutos**, irá redefinir as configurações do BIOS, incluindo a senha. Alternativamente, um **jumper na placa-mãe** pode ser ajustado para redefinir essas configurações conectando pinos específicos.

Para situações em que ajustes de hardware não são possíveis ou práticos, ferramentas **de software** oferecem uma solução. Executar um sistema a partir de um **Live CD/USB** com distribuições como **Kali Linux** fornece acesso a ferramentas como **_killCmos_** e **_CmosPWD_**, que podem ajudar na recuperação da senha do BIOS.

Nos casos em que a senha do BIOS é desconhecida, inseri-la incorretamente **três vezes** geralmente resultará em um código de erro. Este código pode ser usado em sites como [https://bios-pw.org](https://bios-pw.org) para potencialmente recuperar uma senha utilizável.

### Segurança UEFI

Para sistemas modernos que usam **UEFI** em vez do BIOS tradicional, a ferramenta **chipsec** pode ser utilizada para analisar e modificar as configurações do UEFI, incluindo a desativação do **Secure Boot**. Isso pode ser feito com o seguinte comando:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Análise de RAM e Ataques de Cold Boot

A RAM retém dados brevemente após o corte de energia, geralmente por **1 a 2 minutos**. Essa persistência pode ser estendida para **10 minutos** aplicando substâncias frias, como nitrogênio líquido. Durante esse período prolongado, um **dump de memória** pode ser criado usando ferramentas como **dd.exe** e **volatility** para análise.

### Ataques de Acesso Direto à Memória (DMA)

**INCEPTION** é uma ferramenta projetada para **manipulação física de memória** por meio de DMA, compatível com interfaces como **FireWire** e **Thunderbolt**. Ele permite a bypassar procedimentos de login, patcheando a memória para aceitar qualquer senha. No entanto, é ineficaz contra sistemas **Windows 10**.

### Live CD/USB para Acesso ao Sistema

Alterar binários do sistema como **_sethc.exe_** ou **_Utilman.exe_** com uma cópia do **_cmd.exe_** pode fornecer um prompt de comando com privilégios de sistema. Ferramentas como **chntpw** podem ser usadas para editar o arquivo **SAM** de uma instalação do Windows, permitindo alterações de senha.

**Kon-Boot** é uma ferramenta que facilita o login em sistemas Windows sem saber a senha, modificando temporariamente o kernel do Windows ou UEFI. Mais informações podem ser encontradas em [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Lidando com Recursos de Segurança do Windows

#### Atalhos de Inicialização e Recuperação

- **Supr**: Acessar configurações do BIOS.
- **F8**: Entrar no modo de Recuperação.
- Pressionar **Shift** após o banner do Windows pode ignorar a autenticação automática.

#### Dispositivos BAD USB

Dispositivos como **Rubber Ducky** e **Teensyduino** servem como plataformas para criar dispositivos **bad USB**, capazes de executar payloads predefinidos quando conectados a um computador alvo.

#### Cópia de Sombra de Volume

Privilégios de administrador permitem a criação de cópias de arquivos sensíveis, incluindo o arquivo **SAM**, por meio do PowerShell.

### Bypassing da Criptografia BitLocker

A criptografia BitLocker pode ser potencialmente ignorada se a **senha de recuperação** for encontrada em um arquivo de dump de memória (**MEMORY.DMP**). Ferramentas como **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** podem ser utilizadas para esse fim.

### Engenharia Social para Adição de Chave de Recuperação

Uma nova chave de recuperação do BitLocker pode ser adicionada por meio de táticas de engenharia social, convencendo um usuário a executar um comando que adiciona uma nova chave de recuperação composta por zeros, simplificando assim o processo de descriptografia.
