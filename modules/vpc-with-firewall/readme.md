
Cloudwatch search string:
```
{ ( $.event.event_type = "alert"  ) && ( $.event.alert.action = "blocked" ) }
```

LOG_GROUP_NAME=bs-cxone-aws-nfw-alert
aws logs filter-log-events --start-time 1482197400000 --log-group-name $LOG_GROUP_NAME --filter-pattern "{ ( $.event.event_type = "alert"  ) && ( $.event.alert.action = "blocked" ) }" | jq -r ' .events[].message' |  jq ' (.event_timestamp + " " + .event.alert.action + ": " + .event.src_ip + ":" + (.event.src_port|tostring) + " -> "  + .event.dest_ip + ":" + (.event.dest_port|tostring) + " " + .event.tls.sni + .event.http.hostname)'
