while true; do
  echo -e "\n\n--- $(date) ---" >> output.log
  curl https://app1.jack.sandbox.soluzionifutura.it/ >> output.log 2>&1
  sleep 1
done
