#!/bin/bash

groupname=$(id -gn)
if [ "$groupname" != "privileged" ]; then
    echo "ERROR: Script is not being run in privileged terminal!"
    exit 1
fi

echo "Starting sailfishsecretsd in test mode, please wait..."
systemctl --user stop sailfish-secretsd
rm -rf "/home/nemo/.local/share/system/privileged/Secrets/"
sleep 4
(/usr/bin/sailfishsecretsd --test 2>&1 | cat > /dev/null) &
sailfishsecretsdaemonpid=$!
sleep 4s

testcases=('n /home/nemo/manualtests/matrix/001.sh'
           'n /home/nemo/manualtests/matrix/002.sh'
           'n /home/nemo/manualtests/matrix/003.sh'
           'n /home/nemo/manualtests/matrix/004.sh'
           'p /home/nemo/manualtests/matrix/005.sh'
           'p /home/nemo/manualtests/matrix/006.sh'
           'p /home/nemo/manualtests/matrix/007.sh'
           'p /home/nemo/manualtests/matrix/008.sh'
           'n /home/nemo/manualtests/matrix/009.a.sh;p /home/nemo/manualtests/matrix/009.b.sh;n /home/nemo/manualtests/matrix/009.c.sh'
           'n /home/nemo/manualtests/matrix/010.a.sh;p /home/nemo/manualtests/matrix/010.b.sh;n /home/nemo/manualtests/matrix/010.c.sh'
           'n /home/nemo/manualtests/matrix/011.a.sh;p /home/nemo/manualtests/matrix/011.b.sh;n /home/nemo/manualtests/matrix/011.c.sh'
           'n /home/nemo/manualtests/matrix/012.a.sh;p /home/nemo/manualtests/matrix/012.b.sh;n /home/nemo/manualtests/matrix/012.c.sh'
           'n /home/nemo/manualtests/matrix/013.a.sh;r;n /home/nemo/manualtests/matrix/013.b.sh;n /home/nemo/manualtests/matrix/013.c.sh'
           'n /home/nemo/manualtests/matrix/014.a.sh;r;n /home/nemo/manualtests/matrix/014.b.sh;n /home/nemo/manualtests/matrix/014.c.sh'
           'p /home/nemo/manualtests/matrix/015.a.sh;r;n /home/nemo/manualtests/matrix/015.b.sh;p /home/nemo/manualtests/matrix/015.c.sh'
           'n /home/nemo/manualtests/matrix/025.a.sh;n /home/nemo/manualtests/matrix/025.b.sh;n /home/nemo/manualtests/matrix/025.c.sh'
           'n /home/nemo/manualtests/matrix/026.a.sh;n /home/nemo/manualtests/matrix/026.b.sh;n /home/nemo/manualtests/matrix/026.c.sh'
           'n /home/nemo/manualtests/matrix/027.a.sh;n /home/nemo/manualtests/matrix/027.b.sh;n /home/nemo/manualtests/matrix/027.c.sh'
           'n /home/nemo/manualtests/matrix/028.a.sh;n /home/nemo/manualtests/matrix/028.b.sh;n /home/nemo/manualtests/matrix/028.c.sh'
           'p /home/nemo/manualtests/matrix/029.a.sh;p /home/nemo/manualtests/matrix/029.b.sh;p /home/nemo/manualtests/matrix/029.c.sh'
           'p /home/nemo/manualtests/matrix/030.a.sh;p /home/nemo/manualtests/matrix/030.b.sh;p /home/nemo/manualtests/matrix/030.c.sh'
           'p /home/nemo/manualtests/matrix/031.a.sh;p /home/nemo/manualtests/matrix/031.b.sh;p /home/nemo/manualtests/matrix/031.c.sh'
           'p /home/nemo/manualtests/matrix/032.a.sh;p /home/nemo/manualtests/matrix/032.b.sh;p /home/nemo/manualtests/matrix/032.c.sh'
	   'p /home/nemo/manualtests/matrix/033.a.sh;p /home/nemo/manualtests/matrix/033.b.sh;p /home/nemo/manualtests/matrix/033.c.sh'
	   'p /home/nemo/manualtests/matrix/034.a.sh;p /home/nemo/manualtests/matrix/034.b.sh;p /home/nemo/manualtests/matrix/034.c.sh'
	   'p /home/nemo/manualtests/matrix/035.a.sh;p /home/nemo/manualtests/matrix/035.b.sh;p /home/nemo/manualtests/matrix/035.c.sh'
	   'p /home/nemo/manualtests/matrix/036.a.sh;p /home/nemo/manualtests/matrix/036.b.sh;p /home/nemo/manualtests/matrix/036.c.sh'
	   'n /home/nemo/manualtests/matrix/037.a.sh;r;n /home/nemo/manualtests/matrix/037.b.sh;n /home/nemo/manualtests/matrix/037.c.sh'
	   'n /home/nemo/manualtests/matrix/038.a.sh;r;n /home/nemo/manualtests/matrix/038.b.sh;n /home/nemo/manualtests/matrix/038.c.sh'
	  'p /home/nemo/manualtests/matrix/039.a.sh;r;n /home/nemo/manualtests/matrix/039.b.sh;p /home/nemo/manualtests/matrix/039.c.sh')

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

echo "PASS"
kill -9 $sailfishsecretsdaemonpid
sleep 1s
killall sailfishsecretsd
exit 0
