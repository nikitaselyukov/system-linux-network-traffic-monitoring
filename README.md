**Что реализовано**  
- чтение параметров из конфигурационного файла;  
- периодический запуск резервного копирования по расписанию;  
- создание отдельной папки резервной копии с временной меткой;  
- журналирование через systemd / journalctl;  
- ручной запуск, остановка и просмотр статуса через CLI;  
- автозапуск после старта системы;  
- базовые меры по снижению нагрузки на систему.  
**Архитектура**  
flowchart LR  
     A["/etc/snapshotd/snapshotd.conf"] --> B["snapshotd.timer"]  
     B --> C["snapshotd.service"]  
     C --> D["snapshot_worker"]  
     D --> E["Исходный каталог"]  
     D --> F["Каталог резервных копий"]  
     C --> G["journalctl"]  
     H["snapshotctl"] --> A  
     H --> B  
     H --> C  
   
**Структура проекта**  
.  
 ├── code/  
 │   └── snapshot_worker.cpp  
 ├── docs/  
 │   ├── architecture.md  
 │   ├── security.md  
 │   └── testing.md  
 ├── rootfs/  
 │   ├── etc/  
 │   │   ├── snapshotd/  
 │   │   │   └── snapshotd.conf  
 │   │   └── systemd/  
 │   │       └── system/  
 │   │           ├── snapshotd.service  
 │   │           └── snapshotd.timer  
 │   └── usr/  
 │       └── local/  
 │           └── bin/  
 │               └── snapshotctl  
 ├── install.sh  
 └── README.md  
   
**Принцип работы**  
1. Таймер snapshotd.timer запускает сервис через заданный интервал.  
2. Сервис читает SOURCE и TARGET из конфигурационного файла.  
3. Worker создаёт в целевом каталоге новую папку с временной меткой.  
4. Содержимое исходного каталога копируется в эту папку.  
5. Результат фиксируется в системном журнале.  
**Установка**  
sudo ./install.sh  
   
После установки таймер активируется автоматически.  
**Конфигурация**  
Файл конфигурации:  
/etc/snapshotd/snapshotd.conf  
   
Пример:  
SOURCE=/home/your_user/Documents/source_dir  
 TARGET=/home/your_user/Backups  
 FREQUENCY=15min  
   
Параметры:  
- SOURCE — исходный каталог;  
- TARGET — каталог для хранения резервных копий;  
- FREQUENCY — интервал запуска: 30s, 10min, 2h, 1d, 1w и т. п.  
**Команды управления**  
snapshotctl status  
 snapshotctl enable  
 snapshotctl disable  
 snapshotctl run  
 snapshotctl log  
 snapshotctl set source /home/user/Documents/source_dir  
 snapshotctl set target /home/user/Backups  
 snapshotctl set frequency 30min  
   
**Формат резервных копий**  
Каждая копия создаётся в отдельной папке формата:  
2026-04-15_14-30-00  
   
Это исключает перезапись предыдущих резервных копий и упрощает откат к нужному состоянию.  
**Проверка работы**  
snapshotctl status  
sudo cat /etc/snapshotd/snapshotd.conf  
journalctl -u snapshotd.service -n 10 --no-pager  
ls -R /home/your_user/backups  
systemctl list-timers --all | grep snapshotd  
   
**Безопасность**  
- конфигурационный файл устанавливается с правами 640;  
- сервис запускается не под абстрактным user, а под пользователем установки;  
- резервные копии хранятся отдельно от исходного каталога;  
- сервис не получает лишних привилегий (NoNewPrivileges=true).  
# system linux network traffic monitoring

Минималистичный учебный проект мониторинга сетевого трафика в Linux.

В папке проекта только 3 файла:
1. `traffic_monitor.py` — весь код (GUI + логика анализа + iptables)
2. `.gitignore`
3. `README.md`

## Возможности
- Захват пакетов в реальном времени (`scapy`)
- GUI на `tkinter` с таблицами:
  - пакетный лог
  - подозрительные IP
  - заблокированные IP
- Выявление подозрительного трафика по порогам:
  - объём трафика (`SIZE_THR`)
  - количество уникальных портов (`PORT_SCAN_THR`)
- Блокировка/разблокировка IP через `iptables`
- Защита от самоблокировки (localhost, локальные IP, gateway)
- Логирование в `logs/network_monitor.log`

## Установка
```bash
sudo apt update
sudo apt install -y python3 python3-tk python3-scapy iproute2 iptables
```

## Запуск
```bash
sudo -E python3 traffic_monitor.py
```

> Для sniff и iptables обычно нужны права root.
