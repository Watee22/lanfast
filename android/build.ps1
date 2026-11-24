# LanFast Android 构建脚本 —— 无需 Gradle / Android Studio
# 只需要：JDK 8+、Android SDK 的 platforms\android-28 和 build-tools\29.x
# 用法：  powershell -ExecutionPolicy Bypass -File build.ps1 [-Sdk <SDK路径>] [-Install]
param(
    [string]$Sdk = $(if ($env:ANDROID_HOME) { $env:ANDROID_HOME } elseif ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { "$env:LOCALAPPDATA\Android\Sdk" }),
    [string]$Platform = "android-28",
    [string]$BuildTools = "",
    [switch]$Install
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

if (-not (Test-Path $Sdk)) {
    throw "未找到 Android SDK（当前路径：$Sdk）。请设置 ANDROID_HOME 环境变量，或通过 -Sdk <路径> 指定。"
}

if (-not $BuildTools) {
    $BuildTools = (Get-ChildItem "$Sdk\build-tools" | Sort-Object Name -Descending | Select-Object -First 1).Name
}
$bt = "$Sdk\build-tools\$BuildTools"
$androidJar = "$Sdk\platforms\$Platform\android.jar"
if (-not (Test-Path $androidJar)) { throw "找不到 $androidJar" }
if ($env:JAVA_HOME) { $env:PATH = "$env:JAVA_HOME\bin;$env:PATH" }
Write-Host "SDK: $Sdk  build-tools: $BuildTools  platform: $Platform"

function Run($exe, [string[]]$argv) {
    & $exe @argv
    if ($LASTEXITCODE -ne 0) { throw "$exe 失败 (exit $LASTEXITCODE)" }
}

$out = "$here\build"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force "$out\gen", "$out\classes", "$out\dex" | Out-Null

# 1) 资源编译 + 链接（生成 R.java 与基础 apk）
if (-not (Test-Path "$here\res\mipmap-mdpi\ic_launcher.png")) { python "$here\tools\gen_icons.py" }
Run "$bt\aapt2.exe" @("compile", "--dir", "$here\res", "-o", "$out\res.zip")
Run "$bt\aapt2.exe" @("link", "-o", "$out\base.apk", "-I", $androidJar, "--manifest", "$here\AndroidManifest.xml",
    "--java", "$out\gen", "--min-sdk-version", "21", "--target-sdk-version", "28",
    "--version-code", "1", "--version-name", "1.0", "$out\res.zip")

# 2) 编译 Java
$srcs = @(Get-ChildItem -Recurse "$here\src", "$out\gen" -Filter *.java | ForEach-Object { $_.FullName })
Run "javac" (@("-J-Duser.language=en", "-encoding", "UTF-8", "-source", "8", "-target", "8", "-Xlint:-options", "-nowarn",
    "-bootclasspath", $androidJar, "-classpath", "$bt\core-lambda-stubs.jar", "-d", "$out\classes") + $srcs)

# 3) 转 dex
$classes = @(Get-ChildItem -Recurse "$out\classes" -Filter *.class | ForEach-Object { $_.FullName })
Run "$bt\d8.bat" (@("--release", "--min-api", "21", "--lib", $androidJar, "--output", "$out\dex") + $classes)

# 4) 把 classes.dex 放进 apk
Copy-Item "$out\base.apk" "$out\unsigned.apk"
Push-Location "$out\dex"
Run "$bt\aapt.exe" @("add", "$out\unsigned.apk", "classes.dex") | Out-Null
Pop-Location

# 5) 对齐 + 签名（自动生成本地签名证书）
Run "$bt\zipalign.exe" @("-f", "-p", "4", "$out\unsigned.apk", "$out\aligned.apk")
$ks = "$here\lanfast.keystore"
if (-not (Test-Path $ks)) {
    Run "keytool" @("-genkeypair", "-keystore", $ks, "-storepass", "lanfast", "-keypass", "lanfast", "-alias", "lanfast",
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "36500", "-dname", "CN=LanFast")
}
$apk = "$here\LanFast.apk"
Run "$bt\apksigner.bat" @("sign", "--ks", $ks, "--ks-pass", "pass:lanfast", "--key-pass", "pass:lanfast", "--out", $apk, "$out\aligned.apk")
Write-Host "`n构建成功：$apk  ($([math]::Round((Get-Item $apk).Length / 1KB)) KB)" -ForegroundColor Green

if ($Install) { Run "adb" @("install", "-r", $apk) }
