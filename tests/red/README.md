# RED Test Harness

Bu qovluq security gate-lərin **həqiqətən bloklayıb-bloklamadığını** sübut edən
qəsdən zəif nümunələri saxlayır.

## Vacib təhlükəsizlik qeydi

Fayllar `.txt` şəkilçisi ilə saxlanılır ki, **heç vaxt icra olunmasınlar** və
tətbiq build-inə düşməsinlər. RED testi işlətmək üçün fayl müvəqqəti olaraq
`.js` kimi kopyalanır, test bitdikdən sonra silinir.

Buradakı bütün "secret"-lər dummy dəyərlərdir (`DUMMY-NOT-A-REAL-SECRET`) və
`security/gitleaks/gitleaks.toml` allowlist-ində qeydə alınıb — əks halda hər
RED test qaçılmaz olaraq Gate 3-ü bloklayardı.

## Fayllar

| Fayl | Gate | Gözlənilən nəticə |
|---|---|---|
| `sast-vulnerable.js.txt` | Gate 1 (Semgrep) | 7 finding, hamısı HIGH → FAIL |

Qalan gate-lərin RED testləri (SCA, Secret, IaC, Image, DAST, Runtime)
Phase 9-da tam şəkildə qurulacaq.

## İşlətmə

```bash
bash tests/red/run-red-test.sh sast
```
