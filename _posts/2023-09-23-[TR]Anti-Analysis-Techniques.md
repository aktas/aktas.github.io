---
title: Anti Analysis Techniques[TR]
published: true
---

<div style="text-align:center"><img src="/assets/captan.jpg" alt="FlapJack Captain" ></div>

Günümüzde, kötü niyetli yazılım geliştiricileri yazdıkları kötü amaçlı yazılımların incelenmesini zorlaştırmak için "Anti-analiz" olarak adlandırılan teknikleri kullanır. Bu teknikler, malware analistlerin sıkça kullandığı analiz araçlarını ve yöntemlerini etkisiz hale getirmeyi veya karmaşıklaştırmayı amaçlar. Bu araçlar ve yöntemler arasında disassembling, debugging ve virtual machine bulunabilir.

Bu yazıda size öğrendiğim teknikleri göstereceğim. Yazı, yeni teknikler öğrendikçe sürekli olarak güncellenecektir. Kodların tamamına ulaşmak için [bu repo](https://github.com/aktas/Anti-Analysis)'yu ziyaret edin.

### [](#header-2)Anti Disassembly Techniques

Anti-Disassembly tekniği, kodun analiz edilmesini zorlaştırmayı amaçlar ve genellikle kodun çalışma mantığını anlamaya çalışan tersine mühendislik uzmanlarına karşı kullanılır. Bu yöntem, runtime analizde önemini yitirse de, statik analizde işi zorlaştırabilir.

### [](#header-3)Impossible Disassembly

<div style="text-align:center"><img src="/assets/ImpossibleDisassembly.png" alt="FlapJack Captain" ></div>

Resmi incelediğimizde `loc_4046D3` adresinde anlamsız hex ifadeleri görüyoruz. IDA Pro kodu düzgünce okuyamıyor. Burada kodun gizlendiği anlaşılıyor. `loc_4046D3` adresine sıçrayan `jl short near ptr loc_4046D3+2` satırı dikkatimizi çekiyor. Bu kısımda, program çalışma anında `loc_4046D3` adresinden başlayarak `2` bayt sonrasındaki adrese atlayarak çalışıyor. Ancak kullandığımız disassembler araçları, kodu ilk bayttan okumaya başladığı için düzgün şekilde çözümleyemiyor ve karmaşık bir sonuç ortaya çıkıyor.

Her ne kadar tekniğin ismi `Impossible Disassembly` olsa da çözümü oldukça basit. Program runtime da çalışırken `loc_4046D3` adresinin ilk `2` byte'ını es geçtiği için ve disassembler aracı ilk byte'dan okumaya başladığı için yapmamız gerek ilk `2` byte'ı `NOP` kodu ile değiştirmek. Bu işlemi yapmak için hex editor gibi bir araç kullanabilirsiniz. `E9` ve `74` adreslerini `90` ile değiştirdiğimizde disassembler aracımız kodu düzgünce yorumlayabiliyor.

<div style="text-align:center"><img src="/assets/opcode_patching.png" alt="FlapJack Captain" ></div>
<div style="text-align:center"><img src="/assets/ImpossibleDisassembly2.png" alt="FlapJack Captain" ></div>

32 bit programlarda bu tekniği otomatik olarak çözen script'e [bu](https://github.com/aktas/Anti-Analysis/tree/main/ImpossibleDisassembly) linkten ulaşabilirsiniz.

### [](#header-3)API Obfuscation

`GetModuleHandleA` ve `GetProcAddress` işlevleri ile API çağrılarını doğrudan çağırmak yerine program çalışırken dinamik olarak çağırabiliriz. Bu sayede kullanacağımız API çağrılarının statik analizde tespit edilmemesini sağlamış oluruz. Ayrıca bu yöntemi `data obfuscation` ile biraz daha karmaşık hale getirebiliriz. 

```
#include <windows.h>
#include <iostream>
using namespace std;

void dynamicApiResolving(const char* str, const char* str2)
{
	string decryptedString;
	string decryptedString2;

	for (int i = 0; i < strlen(str); i++) {
		decryptedString += str[i] ^ 0x11;
	}
	for (int i = 0; i < strlen(str2); i++) {
		decryptedString2 += str2[i] ^ 0x11;
	}

	const char* szMessage = "Hello World!";
	const char* szCaption = "Hello!";
	HMODULE hModule = GetModuleHandleA(decryptedString2.c_str());
	if (!hModule)
		cout << "error" << endl;
	FARPROC fFuncProc = GetProcAddress(hModule, decryptedString.c_str());
	((int (WINAPI*)(HWND, LPCSTR, LPCSTR, UINT)) fFuncProc)(0, szMessage, szCaption, 0);
	FreeLibrary(hModule);
}

string xorFunc(const char* str) {
	string encryptedString;

	for (int i = 0; i < strlen(str); i++) {
		encryptedString += str[i] ^ 0x11;
	}

	return encryptedString;
}

int main()
{
	
	//cout << xorFunc("MessageBoxA") << endl;
	ShowWindow(GetConsoleWindow(), 0);
	if (FreeConsole()) {
		dynamicApiResolving("\\tbbpvtS~iP", "dbtc\"#?u}}"); // api, dll
	}

	return 0;
}
```


### [](#header-2)Anti Debug Techniques

Anti debug tekniği ile bir programın debugger tarafından incelenmesini veya analiz edilmesini engellemek amaçlanır.

### [](#header-3)IsDebuggerPresent & CheckRemoteDebuggerPresent

`IsDebuggerPresent` ve `CheckRemoteDebuggerPresent`, bir programın bir debugger tarafından incelenip incelenmediğini belirlemek için kullanılır. `CheckRemoteDebuggerPresent` işlevi, belirli bir işlemin PID değerini alarak debugger tarafından incelenip incelenmediğini kontrol eder.

```
#include <iostream>
#include <windows.h>

using namespace std;

int main() {

	if (IsDebuggerPresent()) {
		ExitProcess(0);
	}

	BOOL isDebuggerPresent = false;
	HANDLE hProcess = GetCurrentProcess();
	CheckRemoteDebuggerPresent(hProcess, &isDebuggerPresent);
	if (isDebuggerPresent) {
		ExitProcess(0);
	}

	cout << "Everything's OK" << endl;

	return 0;
}
```

### [](#header-3)BlockInput

`BlockInput` fonksiyonu, kullanıcının giriş aygıtlarını (klavye ve fare) geçici olarak devre dışı bırakma veya etkinleştirme yeteneğine sahiptir. Kod, bu fonksiyonu iki kez çağırarak hata ayıklama aracının bu fonksiyonu engelleyip engellemediğini kontrol etmeye çalışıyor. Normalde, bir hata ayıklama aracı bu tür işlemleri engelleyemez, bu nedenle eğer fonksiyon çağrıları başarılıysa, hata ayıklama aracı var gibi düşünülebilir.

```
#include <iostream>
#include <windows.h>

using namespace std;

bool IsHooked()
{
    BOOL bFirstResult = FALSE, bSecondResult = FALSE;
    __try
    {
        bFirstResult = BlockInput(TRUE);
        bSecondResult = BlockInput(TRUE);
    }
    __finally
    {
        BlockInput(FALSE);
    }
    return bFirstResult && bSecondResult;
}

int main()
{
    if (IsHooked()) {
        cout << "Detect Debugger!" << endl;
    } 
}
```

### [](#header-3)FindWindow

`FindWindow` ile pencere sınıflarının varlığı kontrol edilerek debugger'ın varlığının tespit edilmesi amaçlanır.

```
#include <iostream>
#include <windows.h>
#include <vector>

using namespace std;

const vector<string> vWindowClasses = {
  "antidbg",
  "ID", // Immunity Debugger
  "ntdll.dll", 
  "ObsidianGUI",
  "OLLYDBG",
  "Rock Debugger",
  "SunAwtFrame",
  "Qt5QWindowIcon",
  "WinDbgFrameClass",
  "Zeta Debugger",
  "IDA", 
  "X32Dbg",
  "x64dbg",
};

bool IsDebugged()
{
    for (const string& sWndClass : vWindowClasses) {
        const char* pszWndClass = sWndClass.c_str();
        if (NULL != FindWindowA(pszWndClass, NULL)) {
            return true;
        }
    }
    return false;
}

int main() {
    bool isDebuggerDetected = IsDebugged();

    if (isDebuggerDetected) {
        cout << "Debugger detected!\n";
    } 

    return 0;
}
```

### [](#header-3)RaiseException

`RaiseException` ile eğer debugger tespit edilirse istisna fırlatılarak programın kapatılmasını sağlayabiliriz.

```
#include <Windows.h>
#include <iostream>
using namespace std;
bool Check()
{
    __try
    {
        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
        return true;
    }
    __except (DBG_CONTROL_C == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
}

int main() {
    bool isDebuggerPresent = Check();

    if (!isDebuggerPresent) {
        printf("Debugger is not present.\n");
    }

}
```

### [](#header-3)GetTickCount

`GetTickCount` kullanarak işlem başlangıcı ve bitişi arasındaki süreyi ölçebilir ve eğer belirtilen süreden büyükse programı sonlandırabiliriz. Pek kullanılan bir yöntem olmasada debugger ile program incelenirken aradaki süre artacağından dolayı bu yöntem kullanılabilir.

```
#include <iostream>
#include <windows.h>

using namespace std;
bool IsDebuggedd(DWORD dwNativeElapsed) // milisaniye
{
    DWORD dwStart = GetTickCount();
    // ... 
    return (GetTickCount() - dwStart) > dwNativeElapsed;
}

int main()
{
    if (IsDebuggedd(1000)) {
        cout << "Debugger Detected!" << endl;
    }
}
```

### [](#header-3)QueryPerformanceCounter

`QueryPerformanceCounter` işlevi `GetTickCount` ile aynı amacı taşıyan bir diğer fonksiyonumuz. 

```
#include <iostream>
#include <windows.h>

using namespace std;

bool IsDebugged(DWORD64 qwNativeElapsed) // milisaniye
{
    LARGE_INTEGER liStart, liEnd;
    QueryPerformanceCounter(&liStart);
    // ... 
    QueryPerformanceCounter(&liEnd);
    return (liEnd.QuadPart - liStart.QuadPart) > qwNativeElapsed;
}

int main()
{
    if (IsDebugged(1000)) {
        cout << "Debugger detected!" << endl;
    }
}
```

### [](#header-2)Data Obfuscation

Data Obfuscation ile kötü amaçlı yazılımlara ait kodun gizlenerek analiz edilmesinin zorlaştırılması amaçlanır. Bu işlem için `xor`, `base64`, `AES Encrypt/Decrypt` gibi çeşitli yöntemler kullanılabilir.

### [](#header-3)Base64

`openssl` kütüphanesini kullanarak `base64 encode/decode` işlemlerini yapabiliriz.

```
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <iostream>

std::string base64_encode(const std::string& input) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    return std::string(bufferPtr->data, bufferPtr->length);
}

std::string base64_decode(const std::string& input) {
    BIO* bio, * b64;
    char* buffer = new char[input.size()];
    std::copy(input.begin(), input.end(), buffer);

    bio = BIO_new_mem_buf(buffer, input.size());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int length = BIO_read(bio, buffer, input.size());
    BIO_free_all(bio);

    return std::string(buffer, length);
}

int main() {
    std::string originalText = "To the King!";
    std::string encodedText = base64_encode(originalText);
    std::string decodedText = base64_decode(encodedText);

    std::cout << "Original: " << originalText << std::endl;
    std::cout << "Encoded : " << encodedText << std::endl;
    std::cout << "Decoded : " << decodedText << std::endl;

    return 0;
}
```

### [](#header-3)Xor

Olmazsa olmaz xor :)

```
#include <iostream>
#include <string>

using namespace std;

string xorEncrypt(string key, string message) {
    string ciphertext = "";
    for (int i = 0; i < message.length(); i++)
    {
        ciphertext += message[i] ^ key[i % key.length()];
    }
    return ciphertext;
}

string xorDecrypt(string key, string message) {
    string res = "";
    for (int i = 0; i < message.length(); i++)
    {
        res += message[i] ^ key[i % key.length()];
    }
    return res;
}

int main()
{
    string key = "rivrivriv"; 
    string message = "Ah nerede Vah nerede!";

    string ciphertext = xorEncrypt(key, message);
    cout << ciphertext << endl;

    string res = xorDecrypt(key, ciphertext);
    cout << res << endl;

    return 0;
}
```

### [](#header-3)AES Encrypt/Decrypt

Daha güçlü şifreleme yöntemleri için `AES Encrypt/Decrypt` kullanılabilir. Bu örnek biraz karmaşık gelebilir fakat `encrypt` ve `decrypt` fonksiyonlarının kullanılacağını unutmayın.

```
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <windows.h>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>

using namespace std;

#define DECL_OPENSSL_PTR(tname, free_func) \
    struct openssl_##tname##_dtor {            \
        void operator()(tname* v) {        \
            free_func(v);              \
        }                              \
    };                                 \
    typedef std::unique_ptr<tname, openssl_##tname##_dtor> tname##_t


DECL_OPENSSL_PTR(EVP_CIPHER_CTX, ::EVP_CIPHER_CTX_free);

struct error : public std::exception {
private:
    std::string m_msg;

public:
    error(const std::string& message)
        : m_msg(message) {
    }

    error(const char* msg)
        : m_msg(msg, msg + strlen(msg)) {
    }

    virtual const char* what() const noexcept override {
        return m_msg.c_str();
    }
};

struct openssl_error : public virtual error {
private:
    int m_code = -1;
    std::string m_msg;

public:
    openssl_error(int code, const std::string& message)
        : error(message),
        m_code(code) {
        std::stringstream ss;
        ss << "[" << m_code << "]: " << message;
        m_msg = ss.str();

    }

    openssl_error(int code, const char* msg)
        : error(msg),
        m_code(code) {
        std::stringstream ss;
        ss << "[" << m_code << "]: " << msg;
        m_msg = ss.str();
    }

    const char* what() const noexcept override {
        return m_msg.c_str();
    }
};

static void throw_if_error(int res = 1, const char* file = nullptr, uint64_t line = 0) {

    unsigned long errc = ERR_get_error();
    if (res <= 0 || errc != 0) {
        if (errc == 0) {
            return;
        }
        std::vector<std::string> errors;
        while (errc != 0) {
            std::vector<uint8_t> buf(256);
            ERR_error_string(errc, (char*)buf.data());
            errors.push_back(std::string(buf.begin(), buf.end()));
            errc = ERR_get_error();
        }

        std::stringstream ss;
        ss << "\n";
        for (auto&& err : errors) {
            if (file != nullptr) {
                ss << file << ":" << (line - 1) << " ";
            }
            ss << err << "\n";
        }
        const std::string err_all = ss.str();
        throw openssl_error(errc, err_all);
    }
}

class aes256_cbc {
private:
    std::vector<uint8_t> m_iv;

public:
    explicit aes256_cbc(std::vector<uint8_t> iv)
        : m_iv(std::move(iv)) {
    }

    void encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message, std::vector<uint8_t>& output) const {
        output.resize(message.size() * AES_BLOCK_SIZE);
        int inlen = message.size();
        int outlen = 0;
        size_t total_out = 0;

        EVP_CIPHER_CTX_t ctx(EVP_CIPHER_CTX_new());
        throw_if_error(1, __FILE__, __LINE__);

        // todo: sha256 function
        // const std::vector<uint8_t> enc_key = key.size() != 32 ? sha256(key) : key;

        const std::vector<uint8_t> enc_key = key;

        int res;
        res = EVP_EncryptInit(ctx.get(), EVP_aes_256_cbc(), enc_key.data(), m_iv.data());
        throw_if_error(res, __FILE__, __LINE__);
        res = EVP_EncryptUpdate(ctx.get(), output.data(), &outlen, message.data(), inlen);
        throw_if_error(res, __FILE__, __LINE__);
        total_out += outlen;
        res = EVP_EncryptFinal(ctx.get(), output.data() + total_out, &outlen);
        throw_if_error(res, __FILE__, __LINE__);
        total_out += outlen;

        output.resize(total_out);
    }

    void decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message, std::vector<uint8_t>& output) const {
        output.resize(message.size() * 3);
        int outlen = 0;
        size_t total_out = 0;

        EVP_CIPHER_CTX_t ctx(EVP_CIPHER_CTX_new());
        throw_if_error();

        // todo: sha256 function const std::vector<uint8_t> enc_key = key.size() != 32 ? sha256(key.to_string()) : key;

        // means you have already 32 bytes keys
        const std::vector<uint8_t> enc_key = key;
        std::vector<uint8_t> target_message;
        std::vector<uint8_t> iv;

        iv = m_iv;
        target_message = message;

        int inlen = target_message.size();

        int res;
        res = EVP_DecryptInit(ctx.get(), EVP_aes_256_cbc(), enc_key.data(), iv.data());
        throw_if_error(res, __FILE__, __LINE__);
        res = EVP_DecryptUpdate(ctx.get(), output.data(), &outlen, target_message.data(), inlen);
        throw_if_error(res, __FILE__, __LINE__);
        total_out += outlen;
        res = EVP_DecryptFinal(ctx.get(), output.data() + outlen, &outlen);
        throw_if_error(res, __FILE__, __LINE__);
        total_out += outlen;

        output.resize(total_out);
    }
};

static std::vector<uint8_t> str_to_bytes(const std::string& message) {
    std::vector<uint8_t> out(message.size());
    for (size_t n = 0; n < message.size(); n++) {
        out[n] = message[n];
    }
    return out;
}

static std::string bytes_to_str(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

int main(int, char**) {

    const std::string iv = "1234567890123456";
    const std::string message = "hello world";
    // 32 bytes (256 bits key)
    const std::string key = "passwordpasswordpasswordpassword";


    const aes256_cbc encryptor(str_to_bytes(iv));
    std::vector<uint8_t> enc_result;
    encryptor.encrypt(str_to_bytes(key), str_to_bytes(message), enc_result);

    std::cout << bytes_to_str(enc_result) << std::endl;

    std::vector<uint8_t> dec_result;
    encryptor.decrypt(str_to_bytes(key), enc_result, dec_result);

    std::cout << bytes_to_str(dec_result) << std::endl;
    // output: hello world

    return 0;
}
```




























