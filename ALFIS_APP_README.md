# 🍎 ALFIS macOS Application Bundle

## 📦 Что включено

Этот пакет содержит полноценное macOS приложение ALFIS с поддержкой Apple Silicon.

### 📁 Структура пакета:
```
ALFIS.app/
├── Contents/
│   ├── Info.plist          # Метаданные приложения
│   ├── MacOS/
│   │   ├── ALFIS           # Скрипт запуска
│   │   └── alfis-binary    # Исполняемый файл ALFIS (3.7 MB)
│   └── Resources/
│       └── alfis.icns      # Нативная иконка macOS
```

## 🚀 Как использовать

### 1. **Обычный запуск**
- Дважды кликните на `ALFIS.app`
- Приложение автоматически создаст конфигурацию в `~/.alfis/alfis.toml`
- Появится уведомление macOS о запуске
- ALFIS запустится в обычном режиме

### 2. **Запуск в фоновом режиме**
- Запустите из терминала: `ALFIS.app/Contents/MacOS/ALFIS --background`
- Или создайте ярлык с аргументом `--background`
- Приложение запустится в фоновом режиме
- Управление через Activity Monitor или команды терминала

### 3. **Управление фоновым режимом**
- **Activity Monitor** - найдите процесс `alfis-binary` и остановите
- **Терминал**: `ALFIS.app/Contents/MacOS/alfis-background stop`
- **Статус**: `ALFIS.app/Contents/MacOS/alfis-background status`
- **Перезапуск**: `ALFIS.app/Contents/MacOS/alfis-background restart`

### 4. **Остановка**
- **Обычный режим**: Закройте приложение через Activity Monitor или терминал
- **Фоновый режим**: Используйте команду `ALFIS.app/Contents/MacOS/alfis-background stop`
- Появится уведомление о завершении работы

## ⚙️ Конфигурация

### 📍 Расположение файлов:
- **Конфиг**: `~/.alfis/alfis.toml`
- **База данных**: `~/.alfis/blockchain.db`
- **Ключи**: `~/.alfis/key*.toml` (если есть)

### 🔧 Автоматическая настройка:
Приложение автоматически создает конфиг со следующими настройками:

```toml
# Сеть
[net]
peers = ["peer-v4.alfis.name:4244", "peer-v6.alfis.name:4244"]
listen = "[::]:42440"
public = true

# DNS сервер
[dns]
listen = "127.0.0.1:5311"
threads = 10
forwarders = ["https://dns.adguard.com/dns-query"]

# Майнинг
[mining]
threads = 0  # Автоматически по количеству ядер
lower = true # Низкий приоритет
```

## 🎯 Особенности

### ✅ **Что работает:**
- **Автоматическая настройка** - конфиг создается при первом запуске
- **macOS уведомления** - нативные системные уведомления
- **P2P сеть** - подключение к сети ALFIS
- **DNS сервер** - локальный DNS с блокировкой рекламы
- **Майнинг** - автоматическая настройка по количеству ядер
- **🍎 Фоновый режим** - работа в фоновом режиме без интерфейса
- **📱 Управление через терминал** - команды для управления процессом

### 🔧 **Технические детали:**
- **Архитектура**: arm64 (Apple Silicon native)
- **Размер**: 3.6 MB (несжатое), 1.8 MB (архив)
- **Требования**: macOS 10.15+ (Catalina)
- **Порты**: 42440 (P2P), 5311 (DNS/Web)

## 🎛️ Команды фонового режима

### 📋 **Доступные команды:**
```bash
# Запуск в фоновом режиме
ALFIS.app/Contents/MacOS/ALFIS --background

# Управление через фоновый скрипт
ALFIS.app/Contents/MacOS/alfis-background start    # Запустить
ALFIS.app/Contents/MacOS/alfis-background stop     # Остановить
ALFIS.app/Contents/MacOS/alfis-background restart   # Перезапустить
ALFIS.app/Contents/MacOS/alfis-background status    # Показать статус
```

### 🔄 **Автозапуск в фоне:**
1. Создайте ярлык в `~/Applications/` или `~/Desktop/`
2. Добавьте аргумент `--background` в свойства ярлыка
3. Приложение будет запускаться в фоновом режиме

## 🛠️ Устранение неполадок

### ❌ **Порт занят (Address already in use)**
```bash
# Найдите процесс, использующий порт
lsof -i :5311
lsof -i :42440

# Остановите процесс
kill -9 <PID>
```

### ❌ **Приложение не запускается**
```bash
# Проверьте права доступа
chmod +x ALFIS.app/Contents/MacOS/ALFIS

# Запустите из терминала для диагностики
ALFIS.app/Contents/MacOS/ALFIS
```

### ❌ **Конфиг не создается**
```bash
# Создайте конфиг вручную
mkdir -p ~/.alfis
cd ~/.alfis
ALFIS.app/Contents/MacOS/alfis-binary --generate > alfis.toml
```

## 📋 Системные требования

- **macOS**: 10.15 (Catalina) или новее
- **Архитектура**: Apple Silicon (M1/M2/M3/M4) + Intel Mac
- **Интернет**: Требуется для синхронизации P2P сети
- **Права**: Доступ к сети и файловой системе

## 🎉 Готово к использованию!

Приложение полностью самодостаточно и готово к работе. Просто запустите `ALFIS.app` и наслаждайтесь децентрализованной системой идентификации!

---

**Built with ❤️ for Apple Silicon**