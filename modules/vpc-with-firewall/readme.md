
Cloudwatch search string:
```
{ ( $.event.event_type = "alert"  ) && ( $.event.alert.action = "blocked" ) }
```

Example CLI Search Command:
```
aws logs filter-log-events --start-time 1713475743 --log-group-name /aws/vendedlogs/${DEPLOYMENT_ID}-aws-nfw-alert | jq -r ' .events[].message' |  jq ' (.event.timestamp + " " + .event.alert.action + ": " + .event.src_ip + ":" + (.event.src_port|tostring) + " -> " + .event.proto + "/" + .event.app_proto + " "  + .event.dest_ip + ":" + (.event.dest_port|tostring) + " " + .event.tls.sni + .event.http.hostname) + " " + .event.http.http_user_agent + " " + .event.http.http_method + " " + .event.http.url'
```
