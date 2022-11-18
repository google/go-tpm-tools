#! /bin/bash

if [[ $EXIT_STATUS -eq 3 ]]
then
	# reboot after 2 min
	shutdown --reboot +2
fi

if [[ $EXIT_STATUS -eq 0 ]] || [[ $EXIT_STATUS -eq 1 ]] || [[ $EXIT_STATUS -eq 2 ]]
then
	# poweroff after 2 min
	shutdown --poweroff +2
fi

