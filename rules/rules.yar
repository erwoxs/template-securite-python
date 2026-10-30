rule Suspicious_Downloader
{
    meta:
        author = "esgi"
        description = "Telechargement + execution d'une charge distante"
    strings:
        $dll = "urlmon.dll" nocase
        $api = "URLDownloadToFile" nocase
        $run = "WinExec" nocase
    condition:
        2 of them
}

rule Reverse_Shell
{
    meta:
        author = "esgi"
        description = "Socket sortante + shell de commande"
    strings:
        $ws = "WSASocket" nocase
        $sh = "cmd.exe" nocase
    condition:
        $ws and $sh
}

rule Keylogger
{
    meta:
        author = "esgi"
        description = "Hook clavier"
    strings:
        $hook = "SetWindowsHookEx" nocase
        $key = "GetAsyncKeyState" nocase
    condition:
        any of them
}

rule C2_Gate {
    meta:
        author = "ton_nom"
    strings:
        $gate = "gate.php" nocase
        $c2 = ".example.test" nocase
    condition:
        any of them
}

rule Registry_Persistence {
    strings:
        $run = "CurrentVersion\\Run" nocase
    condition:
        $run
}
