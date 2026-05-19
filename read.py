from datetime import datetime, timedelta

window = timedelta(seconds=60)
threshold  = 5
with open('/var/log/auth.log', 'r') as f:
    count = dict()
    for line in f:
        if('Failed password' in line):
            tmp = line.split()
            if "from" in tmp:
                ip = tmp[tmp.index("from")+1]
                time = datetime.fromisoformat(tmp[0])
                if ip not in count: count[ip] = [time]
                else: 
                    old_len = len(count[ip])
                    count[ip].append(time)
                    count[ip] = [t for t in count[ip]if time - t <=window]
                    new_len = len(count[ip])
                    if old_len<=threshold and new_len >threshold:
                          print("ALERT", ip)   
            else:
                continue