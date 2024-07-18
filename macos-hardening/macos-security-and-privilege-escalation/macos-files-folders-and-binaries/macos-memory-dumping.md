# Dumping de Memória do macOS

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares de roubo**.

O principal objetivo do WhiteIntel é combater invasões de contas e ataques de ransomware resultantes de malwares de roubo de informações.

Você pode acessar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

***

## Artefatos de Memória

### Arquivos de Troca

Arquivos de troca, como `/private/var/vm/swapfile0`, servem como **caches quando a memória física está cheia**. Quando não há mais espaço na memória física, seus dados são transferidos para um arquivo de troca e depois trazidos de volta para a memória física conforme necessário. Vários arquivos de troca podem estar presentes, com nomes como swapfile0, swapfile1, e assim por diante.

### Imagem de Hibernação

O arquivo localizado em `/private/var/vm/sleepimage` é crucial durante o **modo de hibernação**. **Dados da memória são armazenados neste arquivo quando o macOS hiberna**. Ao acordar o computador, o sistema recupera os dados da memória deste arquivo, permitindo que o usuário continue de onde parou.

Vale ressaltar que em sistemas MacOS modernos, este arquivo é tipicamente criptografado por motivos de segurança, tornando a recuperação difícil.

* Para verificar se a criptografia está ativada para o sleepimage, o comando `sysctl vm.swapusage` pode ser executado. Isso mostrará se o arquivo está criptografado.

### Logs de Pressão de Memória

Outro arquivo importante relacionado à memória em sistemas MacOS é o **log de pressão de memória**. Esses logs estão localizados em `/var/log` e contêm informações detalhadas sobre o uso de memória do sistema e eventos de pressão. Eles podem ser particularmente úteis para diagnosticar problemas relacionados à memória ou entender como o sistema gerencia a memória ao longo do tempo.

## Dumping de memória com osxpmem

Para fazer o dumping de memória em uma máquina MacOS, você pode usar [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: As instruções a seguir funcionarão apenas para Macs com arquitetura Intel. Esta ferramenta está arquivada e a última versão foi em 2017. O binário baixado usando as instruções abaixo tem como alvo chips Intel, pois o Apple Silicon não existia em 2017. Pode ser possível compilar o binário para a arquitetura arm64, mas você terá que tentar por conta própria.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Se encontrar este erro: `osxpmem.app/MacPmem.kext falhou ao carregar - (libkern/kext) falha de autenticação (propriedade/ permissões de arquivo); verifique os logs do sistema/kernel para erros ou tente kextutil(8)` Você pode corrigi-lo fazendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Outros erros** podem ser corrigidos permitindo o carregamento do kext em "Segurança e Privacidade --> Geral", apenas **permita**.

Você também pode usar este **oneliner** para baixar o aplicativo, carregar o kext e fazer dump da memória:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares stealers**.

O principal objetivo do WhiteIntel é combater a apropriação de contas e ataques de ransomware resultantes de malwares que roubam informações.

Você pode acessar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
