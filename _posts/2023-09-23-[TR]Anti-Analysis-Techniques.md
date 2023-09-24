---
title: Anti Analysis Techniques[TR]
published: true
---

<div style="text-align:center"><img src="/assets/captan.jpg" alt="FlapJack Captain" ></div>

Günümüzde, kötü niyetli yazılım geliştiricileri yazdıkları kötü amaçlı yazılımların incelenmesini zorlaştırmak için "Anti-analiz" olarak adlandırılan teknikleri kullanır. Bu teknikler, malware analistlerin sıkça kullandığı analiz araçlarını ve yöntemlerini etkisiz hale getirmeyi veya karmaşıklaştırmayı amaçlar. Bu araçlar ve yöntemler arasında disassembling, debugging ve virtual machine bulunabilir.

Bu yazıda size öğrendiğim teknikleri göstereceğim. Yazı, yeni teknikler öğrendikçe sürekli olarak güncellenecektir.

### [](#header-2)Anti Disassembly Techniques

Anti-Disassembly tekniği, kodun analiz edilmesini zorlaştırmayı amaçlar ve genellikle kodun çalışma mantığını anlamaya çalışan tersine mühendislik uzmanlarına karşı kullanılır. Bu yöntem, runtime analizde önemini yitirse de, statik analizde işi zorlaştırabilir.

### [](#header-3)Impossible Disassembly

<div style="text-align:center"><img src="/assets/ImpossibleDisassembly.png" alt="FlapJack Captain" ></div>

Resmi incelediğimizde `loc_4046D3` adresinde anlamsız hex ifadeleri görüyoruz. IDA Pro kodu düzgünce okuyamıyor. Burada kodun gizlendiği anlaşılıyor. `loc_4046D3` adresine sıçrayan `jl short near ptr loc_4046D3+2` satırı dikkatimizi çekiyor. Bu kısımda, program çalışma anında `loc_4046D3` adresinden başlayarak `2` bayt sonrasındaki adrese atlayarak çalışıyor. Ancak kullandığımız disassembler araçları, kodu ilk bayttan okumaya başladığı için düzgün şekilde çözümleyemiyor ve karmaşık bir sonuç ortaya çıkıyor.

Her ne kadar tekniğin ismi `Impossible Disassembly` olsa da çözümü oldukça basit. Program runtime da çalışırken `loc_4046D3` adresinin ilk `2` byte'ını es geçtiği için ve disassembler aracı ilk byte'dan okumaya başladığı için yapmamız gerek ilk `2` byte'ı `NOP` kodu ile değiştirmek. Bu işlemi yapmak için hex editor gibi bir araç kullanabilirsiniz. `E9` ve `74` adreslerini `90` ile değiştirdiğimizde disassembler aracımız kodu düzgünce yorumlayabiliyor.

<div style="text-align:center"><img src="/assets/opcode_patching.png" alt="FlapJack Captain" ></div>
<div style="text-align:center"><img src="/assets/ImpossibleDisassembly2.png" alt="FlapJack Captain" ></div>

32 bit programlarda bu tekniği otomatik olarak çözen script'e [bu](https://github.com/aktas/Anti-Analysis/tree/main/ImpossibleDisassembly) linkten ulaşabilirsiniz.




