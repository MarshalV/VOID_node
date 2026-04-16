# VOID bootstrap-узел

Минимальный **seed** для общей Kademlia-таблицы VOID (`/void/kad/1.0.0`), совместимый с клиентом **VOID p2p-messenger** (libp2p 0.56). Сообщения через этот узел **не** проходят: он только помогает клиентам обмениваться маршрутами в DHT.

## Требования

- [Rust](https://rustup.rs/) (stable)
- Публичный **IPv4** или домен с **A-записью** на ваш роутер/сервер
- На роутере: **проброс TCP** (по умолчанию порт **4001**) на машину, где запущен узел

## Сборка

```powershell
cd C:\Users\banda\Desktop\bootstrap_node
cargo build --release
```

Бинарник: `target\release\void-bootstrap-node.exe`

## Первый запуск

```powershell
cd C:\Users\banda\Desktop\bootstrap_node
.\target\release\void-bootstrap-node.exe
```

При первом запуске создаётся файл **`bootstrap_peer.key`** — **сохраните его и делайте резервную копию**. Если удалить ключ, изменится **PeerId**, и старые multiaddr в `void-bootstrap.txt` у людей перестанут работать.

В консоли будут напечатаны:

- **PeerId**
- шаблон **multiaddr** для клиентов (подставьте свой публичный IP или DNS)

## Порт

По умолчанию слушает **TCP 4001**. Другой порт:

```powershell
$env:LISTEN_PORT = "4002"
.\target\release\void-bootstrap-node.exe
```

На роутере пробросьте тот же TCP-порт.

## Подключение мессенджера

1. Узнайте публичный IP (или используйте `myip.com` и т.п.) либо имя хоста с `dns4`.
2. Одна строка для **`void-bootstrap.txt`** рядом с мессенджером или переменная **`VOID_BOOTSTRAP`**:

```text
/ip4/203.0.113.50/tcp/4001/p2p/12D3KooWxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

или:

```text
/dns4/bootstrap.example.com/tcp/4001/p2p/12D3KooWxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Подставьте **свой** IP/домен, порт и **свой** PeerId из консоли bootstrap-узла.

В приложении VOID: боковая панель **«VOID BOOTSTRAP (DHT)»** → вставить строку → **«Сохранить и применить к DHT»**.

## Логи

Уровень логов через переменную окружения (по умолчанию `info`):

```powershell
$env:RUST_LOG = "debug"
.\target\release\void-bootstrap-node.exe
```

### `WARN libp2p_kad::behaviour: Failed to trigger bootstrap: No known peers`

Это **не ошибка** для узла, который сам является корневым seed: Kademlia один раз пытается «подтянуться» к DHT, но пока **ни одного чужого пира** нет в таблице — вызов `bootstrap()` закономерно не из чего строить маршрут. Клиенты VOID подключаются **к вам** по строке `/ip4/.../tcp/.../p2p/...`; после появления соединений предупреждение обычно больше не повторяется.

Скрыть только эти предупреждения (остальное `info`):

```powershell
$env:RUST_LOG = "info,libp2p_kad::behaviour=error"
.\target\release\void-bootstrap-node.exe
```

### Несколько адресов «слушаем» (192.168.x, 172.x, 127.0.0.1)

Windows показывает все интерфейсы: домашняя сеть, VirtualBox (`192.168.56.x`), Docker/WSL, loopback. В **пробросе порта** на роутере укажите **тот LAN-IP**, где реально крутится узел (часто один `192.168.x.x` из списка).

## Остановка

`Ctrl+C` в окне консоли.

## Запуск в фоне (Windows)

Проще всего оставить открытой консоль или создать ярлык с «рабочей папкой» `C:\Users\banda\Desktop\bootstrap_node`. Для службы можно использовать [NSSM](https://nssm.cc/): указать путь к `void-bootstrap-node.exe`, рабочий каталог — эта папка (чтобы читался `bootstrap_peer.key`).

## Безопасность

- Держите **`bootstrap_peer.key`** в секрете не обязательно для «взлома чата», но от ключа зависит стабильность адреса seed-узла.
- Открывайте на роутере **только** нужный TCP-порт, не пробрасывайте лишнюю подсеть.
