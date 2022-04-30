global ip2ua : table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value:string){
    if(c$http?$user_agent){
        local srcIp = c$id$orig_h;
        local userAgent = to_lower(c$http$user_agent);
        if(srcIp in ip2ua){
            add(ip2ua[srcIp])[userAgent];
        }
        else{
            ip2ua[srcIp] = set(userAgent);
        }
    }
}

event zeek_done(){
    for(x in ip2ua){
        if(|ip2ua[x]| >= 3){
            print fmt("%s is a proxy", x);
        }
    }
}
