# بناء Ascon-C المحسّنة على Windows

الهدف: بناء ثلاث مكتبات DLL من التنفيذ الرسمي المحسّن (opt64)، لاستخدامها
بدل التنفيذ المرجعي بلغة Python. المخرجات متطابقة بايت-ببايت (تحقّقنا: 20/20)،
لكن الأداء أسرع بنحو 280 ضعفاً.

---

## الخطوة 1 — تثبيت مُصرِّف C

خياران، أيّهما أسهل لكِ:

### الخيار (أ): MSYS2 — موصى به
1. نزّلي من: https://www.msys2.org
2. ثبّتيه (التالي، التالي…)
3. افتحي **MSYS2 MINGW64** من قائمة ابدأ
4. نفّذي:
   ```bash
   pacman -Syu                          # لو طلب إغلاق النافذة، أغلقيها وأعيدي فتحها
   pacman -S mingw-w64-x86_64-gcc git
   ```

### الخيار (ب): TDM-GCC — أبسط لكن أقلّ مرونة
1. نزّلي من: https://jmeubank.github.io/tdm-gcc/
2. ثبّتيه مع خيار "Add to PATH"
3. تحقّقي في cmd: `gcc --version`

---

## الخطوة 2 — تنزيل المصدر الرسمي

في نافذة MSYS2 MINGW64 (أو cmd لو استخدمتِ TDM-GCC):

```bash
cd ~
git clone --depth 1 https://github.com/ascon/ascon-c.git
cd ascon-c
```

لو لم يكن git متاحاً، نزّلي ZIP يدويّاً من:
https://github.com/ascon/ascon-c → Code → Download ZIP

---

## الخطوة 3 — بناء المكتبات الثلاث

من داخل مجلّد `ascon-c`:

```bash
# احفظي مسار الترويسات
INC=$PWD/tests

# 1) Ascon-XOF128
cd crypto_hash/asconxof128/opt64
gcc -O3 -shared -o asconxof.dll hash.c permutations.c printstate.c -I. -I$INC
cd ../../..

# 2) Ascon-Hash256
cd crypto_hash/asconhash256/opt64
gcc -O3 -shared -o asconhash.dll hash.c permutations.c printstate.c -I. -I$INC
cd ../../..

# 3) Ascon-AEAD128
cd crypto_aead/asconaead128/opt64
gcc -O3 -shared -o asconaead.dll aead.c permutations.c printstate.c -I. -I$INC
cd ../../..
```

### لو استخدمتِ cmd بدل MSYS2

استبدلي `$PWD/tests` بالمسار الكامل، مثلاً:
```cmd
set INC=C:\Users\<اسمك>\ascon-c\tests
cd crypto_hash\asconxof128\opt64
gcc -O3 -shared -o asconxof.dll hash.c permutations.c printstate.c -I. -I%INC%
```

---

## الخطوة 4 — نقل المكتبات

انسخي الملفّات الثلاثة:
- `asconxof.dll`
- `asconhash.dll`
- `asconaead.dll`

إلى نفس المجلّد الذي فيه `ascon_c.py` وباقي ملفّات المشروع.

---

## الخطوة 5 — التحقّق من التطابق

في مجلّد المشروع:

```cmd
python ascon_c.py
```

**المتوقّع:** `Result: 20/20 checks passed`

هذا يؤكّد أن التنفيذ بلغة C يُنتج مخرجات مطابقة تماماً للتنفيذ المرجعي —
شرط أساسي قبل استخدامه في القياس.

لو ظهر خطأ "Could not find asconxof.dll":
- تأكّدي أن الملفّات في نفس المجلّد
- أو عيّني المتغيّر: `set ASCON_C_DIR=C:\path\to\dlls`

---

## الخطوة 6 — تشغيل القياس بالتنفيذ المحسّن

بعد نجاح 20/20، غيّري سطر الاستيراد في `benchmark_operations.py`:

```python
# من:
from ascon_ref import ascon_xof, ascon_hash, aead_encrypt, aead_decrypt

# إلى:
from ascon_c import ascon_xof, ascon_hash, aead_encrypt, aead_decrypt
```

ثم:
```cmd
python benchmark_operations.py
```

وأرسلي الأرقام الجديدة لتحديث الورقة.

---

## ما يجب ذكره في الورقة

بعد التحوّل، اذكري في قسم التقييم:

> Ascon operations are executed through the official optimized C
> implementation (ascon-c, opt64 variant), invoked from Python via ctypes.
> The wrapper was verified to reproduce the pure-Python reference
> implementation byte-for-byte across XOF, hash, and AEAD operations,
> confirming standard conformance. X25519 and Ed25519 use the cryptography
> library backed by OpenSSL. Both components therefore run as compiled C,
> making the comparison with prior schemes consistent.

---

## ملاحظة مهمّة

احتفظي بملفّ `ascon_ref.py` في المشروع. هو المرجع الذي يثبت التوافق مع
معيار NIST SP 800-232، و`ascon_c.py` يتحقّق ضدّه. وجود الاثنين معاً هو ما
يجعل ادّعاء الالتزام بالمعيار قابلاً للتدقيق.
