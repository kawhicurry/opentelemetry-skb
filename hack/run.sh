sudo echo
cd src/ && rm -f ./opentelemetry-skb && go build && sudo ./opentelemetry-skb 2>&1 | tee run.log