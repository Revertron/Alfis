#!/usr/bin/env osascript
-- ALFIS Tray Manager AppleScript

on run argv
    set alfisPath to POSIX path of (path to me)
    set alfisDir to do shell script "dirname " & quoted form of alfisPath
    set alfisBinary to alfisDir & "/alfis-binary"
    set pidFile to (path to home folder as string) & ".alfis:alfis.pid"
    
    if (count of argv) > 0 then
        set command to item 1 of argv
    else
        set command to "start"
    end if
    
    if command is "start" then
        -- Создаем директорию конфига
        do shell script "mkdir -p ~/.alfis"
        
        -- Проверяем конфиг
        set configFile to (path to home folder as string) & ".alfis:alfis.toml"
        try
            set configExists to (do shell script "test -f ~/.alfis/alfis.toml && echo 'exists' || echo 'not exists'")
            if configExists is "not exists" then
                display dialog "Creating configuration file..." buttons {"OK"} default button "OK" with icon note
                do shell script quoted form of alfisBinary & " --generate > ~/.alfis/alfis.toml"
            end if
        end try
        
        -- Запускаем ALFIS в фоне
        do shell script "cd ~/.alfis && " & quoted form of alfisBinary & " &"
        do shell script "echo $! > ~/.alfis/alfis.pid"
        
        -- Показываем уведомление
        display notification "ALFIS started in background mode" with title "ALFIS" subtitle "P2P Network Active"
        
        -- Создаем меню трея
        createTrayMenu()
        
    else if command is "stop" then
        -- Останавливаем ALFIS
        try
            set pid to do shell script "cat ~/.alfis/alfis.pid 2>/dev/null || echo ''"
            if pid is not "" then
                do shell script "kill " & pid
                do shell script "rm -f ~/.alfis/alfis.pid"
            end if
        end try
        display notification "ALFIS stopped" with title "ALFIS"
        
    else if command is "restart" then
        -- Перезапускаем
        try
            set pid to do shell script "cat ~/.alfis/alfis.pid 2>/dev/null || echo ''"
            if pid is not "" then
                do shell script "kill " & pid
                delay 2
            end if
        end try
        do shell script "rm -f ~/.alfis/alfis.pid"
        display notification "Restarting ALFIS..." with title "ALFIS"
        do shell script "cd ~/.alfis && " & quoted form of alfisBinary & " &"
        do shell script "echo $! > ~/.alfis/alfis.pid"
        
    else if command is "status" then
        -- Проверяем статус
        try
            set pid to do shell script "cat ~/.alfis/alfis.pid 2>/dev/null || echo ''"
            if pid is not "" then
                do shell script "kill -0 " & pid
                display dialog "ALFIS is running (PID: " & pid & ")" buttons {"OK"} default button "OK"
            else
                display dialog "ALFIS is not running" buttons {"OK"} default button "OK"
            end if
        on error
            display dialog "ALFIS is not running" buttons {"OK"} default button "OK"
        end try
    end if
end run

on createTrayMenu()
    tell application "System Events"
        try
            -- Удаляем существующее меню если есть
            delete menu bar item "ALFIS" of menu bar 1
        end try
        
        -- Создаем новое меню трея
        set trayMenu to make new menu bar item of menu bar 1 with properties {name:"ALFIS"}
        set trayMenuItems to make new menu of trayMenu with properties {name:"ALFIS Menu"}
        
        -- Добавляем пункты меню
        make new menu item of trayMenuItems with properties {name:"Show Status", action:"show_status"}
        make new menu item of trayMenuItems with properties {name:"Restart ALFIS", action:"restart"}
        make new menu item of trayMenuItems with properties {name:"Quit ALFIS", action:"quit"}
    end tell
end createTrayMenu
