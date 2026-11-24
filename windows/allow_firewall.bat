@echo off
:: 以管理员身份运行此脚本，仅对同一局域网子网放行 LanFast 端口（UDP 53530 / TCP 53531）
:: 使用 remoteip=localsubnet + profile=any，即使开启 Clash TUN 导致网络被识别为“公用网络”也能正常互通
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
netsh advfirewall firewall delete rule name="LanFast Discovery (UDP 53530)" >nul 2>&1
netsh advfirewall firewall delete rule name="LanFast Transfer (TCP 53531)" >nul 2>&1
netsh advfirewall firewall add rule name="LanFast Discovery (UDP 53530)" dir=in action=allow protocol=UDP localport=53530 remoteip=localsubnet profile=any
netsh advfirewall firewall add rule name="LanFast Transfer (TCP 53531)" dir=in action=allow protocol=TCP localport=53531 remoteip=localsubnet profile=any
echo.
echo LanFast 局域网防火墙规则已添加完成（仅限同子网设备访问）。
pause
