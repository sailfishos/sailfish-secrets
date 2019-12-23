#!/bin/bash

groupname=$(id -gn)
if [ "$groupname" != "privileged" ]; then
    echo "ERROR: Script is not being run in privileged terminal!"
    exit 1
fi

echo "Starting sailfishsecretsd in test mode, please wait..."
systemctl --user stop sailfish-secretsd

USERNAME=$(loginctl list-sessions | grep seat0 | tr -s " " | cut -d " " -f 4)
USERHOME=$(getent passwd $USERNAME | cut -d : -f 6)
rm -rf "~$USERHOME/.local/share/system/privileged/Secrets/"
sleep 4
(/usr/bin/sailfishsecretsd --test 2>&1 | cat > /dev/null) &
sailfishsecretsdaemonpid=$!
sleep 4s

testcases=('n /opt/tests/Sailfish/Crypto/matrix/001.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/002.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/003.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/004.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/005.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/006.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/007.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/008.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/009.a.sh;p /opt/tests/Sailfish/Crypto/matrix/009.b.sh;n /opt/tests/Sailfish/Crypto/matrix/009.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/010.a.sh;p /opt/tests/Sailfish/Crypto/matrix/010.b.sh;n /opt/tests/Sailfish/Crypto/matrix/010.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/011.a.sh;p /opt/tests/Sailfish/Crypto/matrix/011.b.sh;n /opt/tests/Sailfish/Crypto/matrix/011.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/012.a.sh;p /opt/tests/Sailfish/Crypto/matrix/012.b.sh;n /opt/tests/Sailfish/Crypto/matrix/012.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/013.a.sh;r;n /opt/tests/Sailfish/Crypto/matrix/013.b.sh;n /opt/tests/Sailfish/Crypto/matrix/013.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/014.a.sh;r;n /opt/tests/Sailfish/Crypto/matrix/014.b.sh;n /opt/tests/Sailfish/Crypto/matrix/014.c.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/015.a.sh;r;n /opt/tests/Sailfish/Crypto/matrix/015.b.sh;p /opt/tests/Sailfish/Crypto/matrix/015.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/025.a.sh;n /opt/tests/Sailfish/Crypto/matrix/025.b.sh;n /opt/tests/Sailfish/Crypto/matrix/025.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/026.a.sh;n /opt/tests/Sailfish/Crypto/matrix/026.b.sh;n /opt/tests/Sailfish/Crypto/matrix/026.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/027.a.sh;n /opt/tests/Sailfish/Crypto/matrix/027.b.sh;n /opt/tests/Sailfish/Crypto/matrix/027.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/028.a.sh;n /opt/tests/Sailfish/Crypto/matrix/028.b.sh;n /opt/tests/Sailfish/Crypto/matrix/028.c.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/029.a.sh;p /opt/tests/Sailfish/Crypto/matrix/029.b.sh;p /opt/tests/Sailfish/Crypto/matrix/029.c.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/030.a.sh;p /opt/tests/Sailfish/Crypto/matrix/030.b.sh;p /opt/tests/Sailfish/Crypto/matrix/030.c.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/031.a.sh;p /opt/tests/Sailfish/Crypto/matrix/031.b.sh;p /opt/tests/Sailfish/Crypto/matrix/031.c.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/032.a.sh;p /opt/tests/Sailfish/Crypto/matrix/032.b.sh;p /opt/tests/Sailfish/Crypto/matrix/032.c.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/033.a.sh;p /opt/tests/Sailfish/Crypto/matrix/033.b.sh;p /opt/tests/Sailfish/Crypto/matrix/033.c.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/034.a.sh;p /opt/tests/Sailfish/Crypto/matrix/034.b.sh;p /opt/tests/Sailfish/Crypto/matrix/034.c.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/035.a.sh;p /opt/tests/Sailfish/Crypto/matrix/035.b.sh;p /opt/tests/Sailfish/Crypto/matrix/035.c.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/036.a.sh;p /opt/tests/Sailfish/Crypto/matrix/036.b.sh;p /opt/tests/Sailfish/Crypto/matrix/036.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/037.a.sh;r;n /opt/tests/Sailfish/Crypto/matrix/037.b.sh;n /opt/tests/Sailfish/Crypto/matrix/037.c.sh'
           'n /opt/tests/Sailfish/Crypto/matrix/038.a.sh;r;n /opt/tests/Sailfish/Crypto/matrix/038.b.sh;n /opt/tests/Sailfish/Crypto/matrix/038.c.sh'
           'p /opt/tests/Sailfish/Crypto/matrix/039.a.sh;r;n /opt/tests/Sailfish/Crypto/matrix/039.b.sh;p /opt/tests/Sailfish/Crypto/matrix/039.c.sh')

scriptresult=0
runscript() {
    privileged=$1
    scriptfile=$2
    if [ $privileged == "p" ] ; then
        echo "        About to run in privileged terminal: $scriptfile"
        ($scriptfile)
        scriptresult=$?
    else
        echo "        About to run in non-privileged terminal: $scriptfile"
        (exec sg $USERNAME "$scriptfile")
        scriptresult=$?
    fi
}

echo "Running Sailfish::Crypto matrix tests!"
for testcase in "${testcases[@]}" ; do
    echo "Have testcase: $testcase"
    if [[ $testcase == *";"* ]] ; then
        unset scriptslist
        scriptslist=(${testcase//;/ })
        unset currscript
        currscript=""
        for i in "${scriptslist[@]}" ; do
            if [ $i == "p" ] ; then
                currscript+="$i"
            elif [ $i == "n" ] ; then
                currscript+="$i"
            elif [ $i == "r" ] ; then
                echo "    About to restart sailfishsecretsd as part of test, please wait..."
                kill -9 $sailfishsecretsdaemonpid
                sleep 2s
                killall sailfishsecretsd
                (/usr/bin/sailfishsecretsd --test 2>&1 | cat > /dev/null) &
                sailfishsecretsdaemonpid=$!
                sleep 4s
            else
                script="$currscript $i"
                echo "    About to run script: $script within testcase: $testcase"
                runscript $script
                if [ $scriptresult -gt 0 ] ; then
                    echo "    FAIL: $script in $testcase"
                    sleep 1s
                    kill -9 $sailfishsecretsdaemonpid
                    sleep 1s
                    killall sailfishsecretsd
                    exit $scriptresult
                else
                    echo "    PASS: $script in $testcase"
                fi
                currscript=""
                sleep 1s
            fi
        done
    else
        echo "    About to run script: $testcase"
        runscript $testcase
        if [ $scriptresult -gt 0 ] ; then
            echo "    FAIL: $testcase"
            sleep 1s
            kill -9 $sailfishsecretsdaemonpid
            sleep 1s
            killall sailfishsecretsd
            exit $scriptresult
        else
            echo "    PASS: $testcase"
        fi
        sleep 1s
    fi
done

echo "PASS"
kill -9 $sailfishsecretsdaemonpid
sleep 1s
killall sailfishsecretsd
exit 0
