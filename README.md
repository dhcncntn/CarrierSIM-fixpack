# CarrierSIM fix pack

Фикс-пак для **CarrierSIM** (техника AirLift, профиль Vodafone HU по IMSI на iPhone).
Все исправления уже встроены в `carrier.py` — отдельно патчить ничего не нужно.

## Скачать (ссылка постоянная, всегда свежая сборка)

```
https://github.com/dhcncntn/CarrierSIM-fixpack/releases/latest/download/CarrierSIM-fixpack.zip
```

Архив пересобирается автоматически при каждом пуше в `main` (см. `.github/workflows/release.yml`).

## Как запустить

1. Распаковать архив.
2. macOS: `Запуск macOS.command` · Windows: `Запуск Windows.cmd`.
3. При первом запуске скрипт сам создаёт `.venv` и сам скачивает зависимости
   (нужен Python 3.11+; на Windows — x64; iPhone подключить кабелем и нажать «Доверять»).

## Что исправлено

1. «AirTraffic не подтвердил нужные объекты (подтверждено 2 из 3)» — чистка зависших
   path-подобных записей в `OutstandingAssets_*.sqlite` на iPhone до и после каждой операции.
2. Ложные «Books state differs» — sqlite/WAL/SHM/локи Books больше не сравниваются побайтно.
3. Восстановление Books — до трёх проходов-примирений.
4. «Remote file changed during read» — перечитывание дерева до трёх раз.
5. Пользовательские файлы при восстановлении не удаляются.
6. `--recover AUTO` чинит все незавершённые этапы; автовосстановление после обрыва — тоже.
7. Windows: расширенный поиск библиотек Apple (`CoreFoundation.dll`, `AirTrafficHost.dll`)
   с авто-поиском и подробной диагностикой.

Подробности — `README-airtraffic-fix.md` в архиве.

## Если что-то не работает

Вставьте в любой чат-бот (ChatGPT/Claude/DeepSeek) два файла из архива —
`AI-INSTRUCTIONS.md` и `README-airtraffic-fix.md` — плюс текст вашей ошибки:
бот проведёт вас по шагам.

## Авторство и лицензия

- Оригинальный CarrierSIM: **Vladimir B / vlw** (4PDA, topic 1055886, vlwwwwww@gmail.com).
- Техника AirLift — MIT, см. `LICENSE-AirLift.txt`.
- Фикс-пак: **shrek** + AI-ассистент ZCode, 2026-09-29; проверено на iPhone 17 Pro Max / iOS 27.0.1.
- Код публикуется как open source с указанием авторства; весь риск использования — на вас.
