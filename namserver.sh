while(true)
do
    cp /etc/resolv.conf_back /etc/resolv.conf
    echo "Nameserver Changed"
    sleep 600
done