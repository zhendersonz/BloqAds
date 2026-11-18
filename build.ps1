$ErrorActionPreference = "Stop"

$T    = "C:\Users\Henderson\AppData\Local\Temp\opencode"
$Sdk  = "$T\setup\sdk"
$Bt   = "$Sdk\build-tools\34.0.0"
$Plat = "$Sdk\platforms\android-34\android.jar"
$Proj = "$T\adblock"
$env:JAVA_HOME = "$T\setup\jdk"
$env:Path = "$env:JAVA_HOME\bin;$Bt;$env:Path"

Set-Location $Proj
Remove-Item -Recurse -Force out, dex, dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force out, dex, dist | Out-Null

Write-Host "== 1/6 javac =="
javac -encoding UTF-8 --release 8 -cp $Plat -d out (Get-ChildItem src -Recurse -Filter *.java | ForEach-Object FullName)

Write-Host "== 2/6 d8 (dex) =="
& "$Bt\d8.bat" --release --lib $Plat --min-api 22 --output dex (Get-ChildItem out -Recurse -Filter *.class | ForEach-Object FullName)

Write-Host "== 3/6 aapt2 link =="
& "$Bt\aapt2.exe" link -o dist\unsigned.apk -I $Plat --manifest AndroidManifest.xml --min-sdk-version 22 --target-sdk-version 34

Write-Host "== 4/6 inserir classes.dex =="
& "$env:JAVA_HOME\bin\jar.exe" -uf dist\unsigned.apk -C dex classes.dex

Write-Host "== 5/6 zipalign =="
& "$Bt\zipalign.exe" -f 4 dist\unsigned.apk dist\aligned.apk

Write-Host "== 6/6 assinar =="
if (-not (Test-Path keystore.jks)) {
    & "$env:JAVA_HOME\bin\keytool.exe" -genkeypair -keystore keystore.jks -alias bloqads `
        -keyalg RSA -keysize 2048 -validity 10000 `
        -storepass bloqads123 -keypass bloqads123 -dname "CN=BloqAds"
}
& "$Bt\apksigner.bat" sign --ks keystore.jks --ks-pass pass:bloqads123 --key-pass pass:bloqads123 `
    --out "C:\Users\Henderson\Desktop\BloqAds.apk" dist\aligned.apk
& "$Bt\apksigner.bat" verify --print-certs "C:\Users\Henderson\Desktop\BloqAds.apk"

Get-Item "C:\Users\Henderson\Desktop\BloqAds.apk" | Select-Object Name, Length
Write-Host "OK: APK na Area de Trabalho"
