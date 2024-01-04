# Extensões do Sistema macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Extensões de Sistema / Framework de Segurança de Endpoint

Diferentemente das Extensões de Kernel, as **Extensões de Sistema são executadas no espaço do usuário** em vez de no espaço do kernel, reduzindo o risco de uma falha do sistema devido a mau funcionamento da extensão.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Existem três tipos de extensões de sistema: Extensões **DriverKit**, Extensões de **Rede** e Extensões de **Segurança de Endpoint**.

### **Extensões DriverKit**

DriverKit é um substituto para extensões de kernel que **fornecem suporte a hardware**. Ele permite que drivers de dispositivos (como USB, Serial, NIC e drivers HID) sejam executados no espaço do usuário em vez de no espaço do kernel. O framework DriverKit inclui **versões no espaço do usuário de certas classes do I/O Kit**, e o kernel encaminha eventos normais do I/O Kit para o espaço do usuário, oferecendo um ambiente mais seguro para a execução desses drivers.

### **Extensões de Rede**

Extensões de Rede fornecem a capacidade de personalizar comportamentos de rede. Existem vários tipos de Extensões de Rede:

* **App Proxy**: Utilizado para criar um cliente VPN que implementa um protocolo VPN personalizado orientado a fluxo. Isso significa que ele lida com o tráfego de rede com base em conexões (ou fluxos) em vez de pacotes individuais.
* **Tunnel de Pacotes**: Utilizado para criar um cliente VPN que implementa um protocolo VPN personalizado orientado a pacotes. Isso significa que ele lida com o tráfego de rede com base em pacotes individuais.
* **Filtrar Dados**: Utilizado para filtrar "fluxos" de rede. Pode monitorar ou modificar dados de rede no nível do fluxo.
* **Filtrar Pacotes**: Utilizado para filtrar pacotes de rede individuais. Pode monitorar ou modificar dados de rede no nível do pacote.
* **Proxy DNS**: Utilizado para criar um provedor DNS personalizado. Pode ser usado para monitorar ou modificar solicitações e respostas DNS.

## Framework de Segurança de Endpoint

Segurança de Endpoint é um framework fornecido pela Apple no macOS que oferece um conjunto de APIs para segurança do sistema. É destinado ao uso por **fornecedores de segurança e desenvolvedores para construir produtos que possam monitorar e controlar a atividade do sistema** para identificar e proteger contra atividades maliciosas.

Este framework fornece uma **coleção de APIs para monitorar e controlar a atividade do sistema**, como execuções de processos, eventos do sistema de arquivos, eventos de rede e kernel.

O núcleo deste framework é implementado no kernel, como uma Extensão de Kernel (KEXT) localizada em **`/System/Library/Extensions/EndpointSecurity.kext`**. Este KEXT é composto por vários componentes-chave:

* **EndpointSecurityDriver**: Atua como o "ponto de entrada" para a extensão de kernel. É o principal ponto de interação entre o OS e o framework de Segurança de Endpoint.
* **EndpointSecurityEventManager**: Este componente é responsável por implementar ganchos do kernel. Ganchos do kernel permitem que o framework monitore eventos do sistema interceptando chamadas de sistema.
* **EndpointSecurityClientManager**: Gerencia a comunicação com clientes no espaço do usuário, mantendo o controle de quais clientes estão conectados e precisam receber notificações de eventos.
* **EndpointSecurityMessageManager**: Envia mensagens e notificações de eventos para clientes no espaço do usuário.

Os eventos que o framework de Segurança de Endpoint pode monitorar são categorizados em:

* Eventos de arquivo
* Eventos de processo
* Eventos de socket
* Eventos de kernel (como carregar/descarregar uma extensão de kernel ou abrir um dispositivo I/O Kit)

### Arquitetura do Framework de Segurança de Endpoint

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt=""><figcaption></figcaption></figure>

**Comunicação no espaço do usuário** com o framework de Segurança de Endpoint acontece através da classe IOUserClient. Duas subclasses diferentes são usadas, dependendo do tipo de chamador:

* **EndpointSecurityDriverClient**: Requer a autorização `com.apple.private.endpoint-security.manager`, que é mantida apenas pelo processo do sistema `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Requer a autorização `com.apple.developer.endpoint-security.client`. Normalmente seria usada por software de segurança de terceiros que precisa interagir com o framework de Segurança de Endpoint.

As Extensões de Segurança de Endpoint:**`libEndpointSecurity.dylib`** é a biblioteca C que as extensões de sistema usam para se comunicar com o kernel. Esta biblioteca usa o I/O Kit (`IOKit`) para se comunicar com o KEXT de Segurança de Endpoint.

**`endpointsecurityd`** é um daemon do sistema chave envolvido na gestão e lançamento de extensões de sistema de segurança de endpoint, particularmente durante o processo de inicialização precoce. **Apenas extensões de sistema** marcadas com **`NSEndpointSecurityEarlyBoot`** em seu arquivo `Info.plist` recebem esse tratamento de inicialização precoce.

Outro daemon do sistema, **`sysextd`**, **valida extensões de sistema** e as move para os locais apropriados do sistema. Em seguida, solicita ao daemon relevante para carregar a extensão. O **`SystemExtensions.framework`** é responsável por ativar e desativar extensões de sistema.

## Bypassando ESF

ESF é usado por ferramentas de segurança que tentarão detectar um red teamer, então qualquer informação sobre como isso poderia ser evitado é interessante.

### CVE-2021-30965

O fato é que a aplicação de segurança precisa ter permissões de **Acesso Total ao Disco**. Então, se um atacante pudesse remover isso, ele poderia impedir o software de funcionar:
```bash
tccutil reset All
```
Para **mais informações** sobre este bypass e relacionados, confira a palestra [#OBTS v5.0: "O Calcanhar de Aquiles do EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

No final, isso foi corrigido ao dar a nova permissão **`kTCCServiceEndpointSecurityClient`** ao aplicativo de segurança gerenciado por **`tccd`**, então `tccutil` não vai limpar suas permissões impedindo que ele seja executado.

## Referências

* [**OBTS v3.0: "Segurança & Insegurança do Endpoint" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
