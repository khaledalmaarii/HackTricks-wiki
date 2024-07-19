# Infravermelho

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

## Como o Infravermelho Funciona <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**A luz infravermelha é invisível para os humanos**. O comprimento de onda do IR varia de **0,7 a 1000 micrômetros**. Os controles remotos domésticos usam um sinal IR para transmissão de dados e operam na faixa de comprimento de onda de 0,75..1,4 micrômetros. Um microcontrolador no controle remoto faz um LED infravermelho piscar com uma frequência específica, transformando o sinal digital em um sinal IR.

Para receber sinais IR, um **fotoreceptor** é utilizado. Ele **converte a luz IR em pulsos de tensão**, que já são **sinais digitais**. Normalmente, há um **filtro de luz escura dentro do receptor**, que permite **apenas a passagem do comprimento de onda desejado** e elimina o ruído.

### Variedade de Protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Os protocolos IR diferem em 3 fatores:

* codificação de bits
* estrutura de dados
* frequência portadora — frequentemente na faixa de 36..38 kHz

#### Formas de codificação de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codificação por Distância de Pulso**

Os bits são codificados modulando a duração do espaço entre os pulsos. A largura do pulso em si é constante.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codificação por Largura de Pulso**

Os bits são codificados pela modulação da largura do pulso. A largura do espaço após a explosão do pulso é constante.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codificação de Fase**

É também conhecida como codificação Manchester. O valor lógico é definido pela polaridade da transição entre a explosão do pulso e o espaço. "Espaço para explosão de pulso" denota lógica "0", "explosão de pulso para espaço" denota lógica "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinação dos anteriores e outras exóticas**

{% hint style="info" %}
Existem protocolos IR que estão **tentando se tornar universais** para vários tipos de dispositivos. Os mais famosos são RC5 e NEC. Infelizmente, o mais famoso **não significa o mais comum**. No meu ambiente, encontrei apenas dois controles remotos NEC e nenhum RC5.

Os fabricantes adoram usar seus próprios protocolos IR únicos, mesmo dentro da mesma gama de dispositivos (por exemplo, caixas de TV). Portanto, controles remotos de diferentes empresas e às vezes de diferentes modelos da mesma empresa, não conseguem funcionar com outros dispositivos do mesmo tipo.
{% endhint %}

### Explorando um sinal IR

A maneira mais confiável de ver como o sinal IR do controle remoto se parece é usar um osciloscópio. Ele não demodula ou inverte o sinal recebido, ele é apenas exibido "como está". Isso é útil para testes e depuração. Vou mostrar o sinal esperado com o exemplo do protocolo IR NEC.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Normalmente, há um preâmbulo no início de um pacote codificado. Isso permite que o receptor determine o nível de ganho e o fundo. Também existem protocolos sem preâmbulo, por exemplo, Sharp.

Em seguida, os dados são transmitidos. A estrutura, o preâmbulo e o método de codificação de bits são determinados pelo protocolo específico.

O **protocolo IR NEC** contém um comando curto e um código de repetição, que é enviado enquanto o botão é pressionado. Tanto o comando quanto o código de repetição têm o mesmo preâmbulo no início.

O **comando NEC**, além do preâmbulo, consiste em um byte de endereço e um byte de número de comando, pelos quais o dispositivo entende o que precisa ser realizado. Os bytes de endereço e número de comando são duplicados com valores inversos, para verificar a integridade da transmissão. Há um bit de parada adicional no final do comando.

O **código de repetição** tem um "1" após o preâmbulo, que é um bit de parada.

Para **lógica "0" e "1"**, o NEC usa Codificação por Distância de Pulso: primeiro, uma explosão de pulso é transmitida, após a qual há uma pausa, cuja duração define o valor do bit.

### Ar Condicionados

Diferente de outros controles remotos, **os ar condicionados não transmitem apenas o código do botão pressionado**. Eles também **transmitem todas as informações** quando um botão é pressionado para garantir que a **máquina de ar condicionado e o controle remoto estejam sincronizados**.\
Isso evitará que uma máquina configurada para 20ºC seja aumentada para 21ºC com um controle remoto, e então, quando outro controle remoto, que ainda tem a temperatura como 20ºC, for usado para aumentar mais a temperatura, ela "aumentará" para 21ºC (e não para 22ºC pensando que está em 21ºC).

### Ataques

Você pode atacar o Infravermelho com Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referências

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
