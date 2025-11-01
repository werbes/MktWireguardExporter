/system script
add dont-require-permissions=no name=WireGuardPeer owner=ifwm policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="# C\
    onfiguration\r\
    \n:local wgInterface \"ClientVPN\"\r\
    \n:local endpoint \"PU.BL.IC.IP\"\r\
    \n:local endpointPort 13231\r\
    \n:local allowedIPs \"PRI.VATE.SUB.NET/24\"\r\
    \n:local ipBase \"CL.IE.NT.IP.\"\r\
    \n:local lastFile \"last_peer_ip.txt\"\r\
    \n\r\
    \n# Check if the file exists\r\
    \n:local lastOctet 1\r\
    \n:if ([:len [/file find name=\$lastFile]] > 0) do={\r\
    \n    :local fileId [/file find name=\$lastFile]\r\
    \n    :local content [/file get \$fileId contents]\r\
    \n    :set lastOctet [:tonum \$content]\r\
    \n}\r\
    \n\r\
    \n# Increment last octet\r\
    \n:set lastOctet (\$lastOctet + 1)\r\
    \n:if (\$lastOctet > 254) do={ :set lastOctet 2 }\r\
    \n\r\
    \n# Create new peer IP\r\
    \n:local peerIP (\$ipBase . \$lastOctet . \"/32\")\r\
    \n\r\
    \n# Add peer\r\
    \n/interface/wireguard/peers add interface=\$wgInterface name=(\$ipBase . \$\
    lastOctet) allowed-address=(\$peerIP . \",\" . \$allowedIPs) endpoint-addres\
    s=\$endpoint endpoint-port=\$endpointPort persistent-keepalive=25s private-k\
    ey=auto client-address=\$peerIP preshared-key=auto responder=yes client-dns=\
    10.126.1.11\r\
    \n# Save last used IP to file\r\
    \n:if ([:len [/file find name=\$lastFile]] > 0) do={\r\
    \n    /file remove \$lastFile\r\
    \n}\r\
    \n:delay 1s\r\
    \n/file print file=\$lastFile\r\
    \n:delay 1s\r\
    \n/file set \$lastFile contents=\"\$lastOctet\""
/
:for i from=1 to=250 do={ /system script run WireGuardPeer } 
