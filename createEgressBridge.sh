# Usage: transfer_addrs src dst
# Move all IP addresses (including aliases) from device $src to device $dst.
transfer_addrs () {
    local src=$1
    local dst=$2
    # Don't bother if $dst already has IP addresses.
    if ip addr show dev ${dst} | egrep -q '^ *inet ' ; then
        return
    fi
    # Address lines start with 'inet' and have the device in them.
    # Replace 'inet' with 'ip addr add' and change the device name $src
    # to 'dev $src'.
    ip addr show dev ${src} | egrep '^ *inet ' | sed -e "
s/inet/ip addr add/
s@\([0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/[0-9]\+\)@\1@
s/${src}/dev ${dst}/
" | sh -e
    ip addr show dev ${src} | egrep '^ *inet ' | sed -e "
s/inet/ip addr del/
s@\([0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/[0-9]\+\)@\1@
s/${src}/dev ${src}/
" | sh -e
    # Remove automatic routes on destination device
#    ip route list | sed -ne "
#/dev ${dst}\( \|$\)/ {
#  s/^/ip route del /
#  p
#}" | sh -e
}

# Usage: transfer_routes src dst
# Get all IP routes to device $src, delete them, and
# add the same routes to device $dst.
# The original routes have to be deleted, otherwise adding them
# for $dst fails (duplicate routes).
transfer_routes () {
    local src=$1
    local dst=$2
    # List all routes and grep the ones with $src in.
    # Stick 'ip route del' on the front to delete.
    # Change $src to $dst and use 'ip route add' to add.
    ip route list | sed -ne "
/dev ${src}\( \|$\)/ {
  h
  s/^/ip route del /
  P
  g
  s/${src}/${dst}/
  s/^/ip route add /
  P
  d
}" | sh -e
}

ip link add name $2 type bridge
ip link set $2 up
ip link set $1 master $2
ip tuntap add dev $3 mode tap user $4 group $4
ip link set $3 up
ip link set $3 master $2
transfer_addrs $1 $2
transfer_routes $1 $2
