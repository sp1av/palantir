#!/bin/bash
scan_id=$SCAN_ID_SPLAV
uuid=$CONTROL_SPLAV
containers=($LISTCONTAINERS_SPLAV)
ports=($LISTPORTS_SPLAV)
ip=$HOSTIP_SPLAV
hash='$SPLAVHASH'

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

download_script http://$ip:1703/static/bin/curl > /tmp/curl
download_script http://$ip:1703/static/bin/openssh > /tmp/openssh
download_script http://$ip:1703/static/bin/listener > /tmp/listener
download_script http://$ip:1703/static/bin/ssh_key > /tmp/ssh_key

for i in "${!containers[@]}"; do
    container="${containers[$i]}"
    docker cp /tmp/curl $container:/tmp/curl
    docker cp /tmp/openssh $container:/tmp/openssh
    docker cp /tmp/listener $container:/tmp/listener
    docker cp /tmp/ssh_key $container:/tmp/id_ed25519
    curl -X POST -d "scan_id=$scan_id" -d "uuid=$uuid" -d "data=$(docker inspect $container)" http://$ip:1703/send_data/$container
done


for i in "${!containers[@]}"; do
    container="${containers[$i]}"
	  port="${ports[$i]}"

    docker exec -i "$container" sh -c "chmod +x /tmp/curl"
    docker exec -i "$container" sh -c "chmod 600 /tmp/id_ed25519"
    docker exec -i "$container" sh -c "chmod +x /tmp/openssh"
    docker exec -i "$container" sh -c "chmod +x /tmp/listener"

    docker exec -id "$container" sh -c "setsid /tmp/openssh -o StrictHostKeyChecking=no -i /tmp/id_ed25519 -R localhost:\"$port\":localhost:16139 stuff@\"$ip\" -p 12936 -N > /dev/null 2>&1 &"

    docker exec -id "$container" sh -c "setsid /tmp/listener '$hash' &"

done

sleep 5

curl -X POST -d "scan_id=$scan_id" -d "uuid=$uuid"  http://$ip:1703/api/ready


