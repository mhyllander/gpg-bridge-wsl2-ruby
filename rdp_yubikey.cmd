@echo off
echo "Preparing to use Yubikey in remote session, stopping local services"

gpg-connect-agent "scd killscd" killagent /bye
taskkill /F /IM scdaemon.exe
taskkill /F /IM gpg-agent.exe

net stop CertPropSvc
net stop ScardSvr
net start ScardSvr

echo "Verify that the Yubikey is found by Kleopatra or 'gpg --card-status' in the remote session"
rem timeout 5
rem pause

