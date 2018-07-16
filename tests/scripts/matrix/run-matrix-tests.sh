#!/bin/bash

groupname=$(id -gn)
if [ "$groupname" != "privileged" ]; then
    echo "ERROR: Script is not being run in privileged terminal!"
    exit 1
fi

echo "Starting sailfishsecretsd in test mode, please wait..."
systemctl --user stop sailfish-secretsd
rm -rf "/home/nemo/.local/share/system/privileged/Secrets/"
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
           'p /opt/tests/Sailfish/Crypto/matrix/015.a.sh;r;n /opt/tests/Sailfish/Crypto/matrix/015.b.sh;p /opt/tests/Sailfish/Crypto/matrix/015.c.sh')

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
        (exec sg nemo "$scriptfile")
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

echo "\nPASS\n"
kill -9 $sailfishsecretsdaemonpid
sleep 1s
killall sailfishsecretsd
exit 0
