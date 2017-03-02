#!/bin/sh
# Why is this a shell script instead of Perl?  Trinux does not come with perl.
# Trinux is actually rather useful too.
# 
# I don't know how well this script works.  I've never really used it.

# Parameters
seed=0;			# Starting random seed
packets=10000		# How many packets to send before testing connectivity
pingtarget=expert.cc.purdue.edu		# Who do we ping to see if we still have
					# connectivity.
wgettarget=http://www.microsoft.com/index # What url should we fetch to
					# test connectivity...  Waste
					# mickeysoft's bandwidth :-)

PATH=${PATH}:/usr/local/bin


if test "x$#" = "x0" ; then
	echo "Usage:  $0  [isic|tcpsic|udpsic|icmpsic]  <options>"
	exit
fi

program="$* -p ${packets}"

while ( true ); do
	run="$program -r ${seed}"
	$run
	if test $? -ne 0 ; then
		exit
	fi


	# Test connectivity
	echo "Testing connectivity"
	ping -c5 -i1 -n ${pingtarget}
	if test $? -ne 0 ; then
		echo "ICMP Connectivity failed on seed $seed."
		exit
	fi
	wget -t2 -T30 -w10 ${wgettarget}
	if test $? -ne 0 ; then
		echo "TCP Connectivity failed on seed $seed."
		exit
	fi
	rm index
	(( seed=seed+1 ))
done
