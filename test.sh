#!/bin/sh
#set -x
set -e

msg() {
  echo $* >&2
}

testok() {
  msg spor $*
  if ! eval ../spor $* ; then
    echo "test failed"
    return 1;
  fi
}

testno() {
  msg ! spor $*
  if eval ../spor $* ; then
    msg "test succeeded; should have failed"
    return 1;
  fi
}

same() {
  msg diff -q $1 $2
  if ! diff -q $1 $2 >/dev/null; then
    msg "files differ; should be identical"
    return 1;
  fi
}

notsame() {
  msg ! diff -q $1 $2
  if  diff -q $1 $2 >/dev/null; then
    msg "files are identical; should differ"
    return 1;
  fi
}

d=./testfiles

rm -r $d || true
mkdir -p $d || true

cd $d

echo 'hello world' > msg
echo "Hell0 W0rld" > msg2

echo 'password' > pwfile
echo 'Passw0rd' > pwfile2

msg
msg "-- symmetric encryption --"
testok "'3p e' 3<pwfile <msg >msg.s0"
testok "'3p d' 3<pwfile <msg.s0 >msgout"
same msg msgout

testok "'3p d' 3<pwfile2 <msg.s0 >msgout"
notsame msg msgout

msg
msg "-- I/O redirection --"
testok "'3p 4i d' 3<pwfile 4<msg.s0 >msgout"
same msg msgout

testok "'3p 4o d' 3<pwfile <msg.s0 4>msgout"
same msg msgout

msg
msg "-- key generation --"
testok "'k bx p 3vx' <pwfile >pubkey  3>privkey"
testok "'k bx p 3vx' <pwfile2 >pub2key 3>priv2key"
testok "'bm' < pub2key"
testok "'3p vm' <privkey 3<pwfile"
testno "'3p vm' <privkey 3<pwfile2"

msg
msg "-- key management --"
testok "'3p vm 4p 5vx' <privkey 3<pwfile 4<pwfile2 5>privkey.pw2"
testok "'3p 4vm 5g' 3<pwfile2 4<privkey.pw2 <msg 5>msg.sig"
testok "'4bm 5f' 4<pubkey <msg 5<msg.sig"
testok "'3p vm 4bx' 3<pwfile <privkey 4>pubtest"
same pubkey pubtest
testno "'bm 3p 4vx' 3<pwfile <pubkey 4>privtest"

msg
msg "-- signatures/verification --"
testok "'3p 4vm 5g' 3<pwfile 4<privkey <msg 5>msg.sig"
testok "'3p 4vm 5g' 3<pwfile 4<privkey <msg2 5>msg2.sig"
testok "'3p 4vm 6i 5g' 3<pwfile2 4<priv2key 6<msg 5>msg.sig2"
testok "'3p 4vm 6i g' 3<pwfile2 4<priv2key 6<msg2 >msg2.sig2"

testok "'4bm 5f' 4<pubkey <msg 5<msg.sig"
testok "'4bm 5f' 4<pubkey <msg2 5<msg2.sig"
testok "'4bm 6i 5f' 4<pub2key 6<msg 5<msg.sig2"
testok "'4bm 6i f' 4<pub2key 6<msg2 <msg2.sig2"

testno "'4bm 5f' 4<pubkey <msg 5<msg2.sig"
testno "'4bm 5f' 4<pubkey <msg 5<msg.sig2"
testno "'4bm 5f' 4<pubkey <msg2 5<msg.sig"

msg
msg "-- asymmetric encryption --"
testok "'3bm E' 3<pubkey <msg >msg.s0"
testok "'3bm 4o E' 3<pubkey <msg2 4>msg2.s0"

# correct key, pw: works
testok "'3p 4vm D' 3<pwfile 4<privkey <msg.s0 >msgout"
same msg msgout 
testok "'3p 4vm 5i 6o D' 3<pwfile 4<privkey 5<msg2.s0 6>msg2out"
same msg2 msg2out

# wrong pw,wrong keytype: fail
testno "'3p 4vm D' 3<pwfile 4<priv2key <msg.s0 >msgout"
testno "'3p 4vm D' 3<pwfile 4<pubkey <msg.s0 >msgout"

# wrong keyfile/pw (but match each other): bad output
testok "'3p 4vm D' 3<pwfile2 4<priv2key <msg.s0 >msgout"
notsame msg msgout

# done!
msg
msg "-- tests complete --"
