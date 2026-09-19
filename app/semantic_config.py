"""Semantic RouterOS configuration comparison helpers."""

import re


AREA_RULES=(
    ("/ip dns","DNS"),
    ("/ip route","Routing"),
    ("/ip firewall nat","NAT"),
    ("/ip firewall filter","Firewall filter"),
    ("/ip firewall mangle","Firewall mangle"),
    ("/ip address","IP addressing"),
    ("/interface vlan","VLAN"),
    ("/interface bridge","Bridge"),
    ("/interface ethernet","Ethernet"),
    ("/interface wireguard","WireGuard"),
    ("/interface pppoe-client","PPPoE"),
    ("/ip dhcp-server","DHCP server"),
    ("/ip dhcp-client","DHCP client"),
    ("/ip pool","IP pool"),
    ("/system identity","System identity"),
    ("/system clock","System clock"),
    ("/system ntp","NTP"),
    ("/ip service","Management services"),
    ("/user","Users"),
)


def _area(path:str)->str:
    low=(path or "").lower()
    for prefix,label in AREA_RULES:
        if low.startswith(prefix):
            return label
    if low.startswith("/interface"):
        return "Interfaces"
    if low.startswith("/ip"):
        return "IP configuration"
    if low.startswith("/system"):
        return "System"
    return (path or "Other").strip("/") or "Other"


def _clean(line:str)->str:
    return re.sub(r"\s+"," ",(line or "").strip())


def _parse(content:str):
    path=""
    rows=[]
    for raw in (content or "").splitlines():
        line=_clean(raw)
        if not line or line.startswith("#"):
            continue
        if line.startswith("/"):
            if " " not in line:
                path=line
                continue
            # RouterOS terse exports commonly put the command on the same line.
            parts=line.rsplit(" ",1)
            if parts[-1].split("=",1)[0] in {"add","set","remove","enable","disable"}:
                path,cmd=parts[0],parts[1]
                rows.append((path,cmd))
                continue
            # Prefer the longest path prefix ending before an operation token.
            m=re.match(r"^(.*?)(?:\s+)(add|set|remove|enable|disable)(\s+.*)?$",line,re.I)
            if m:
                path=m.group(1)
                rows.append((path,(m.group(2)+(m.group(3) or "")).strip()))
                continue
            path=line
            continue
        rows.append((path,line))
    return rows


def _selector(cmd:str)->str:
    cmd=_clean(cmd)
    if not cmd:return ""
    op=cmd.split(" ",1)[0].lower()
    rest=cmd[len(op):].strip()
    if op=="set":
        # Match the stable selector portion before ordinary properties.
        if rest.startswith("["):
            depth=0
            for i,ch in enumerate(rest):
                if ch=="[":depth+=1
                elif ch=="]":
                    depth-=1
                    if depth==0:
                        return f"set {rest[:i+1]}"
        first=rest.split(" ",1)[0]
        return f"set {first}"
    if op in {"remove","enable","disable"}:
        return f"{op} {rest.split(' ',1)[0] if rest else ''}".strip()
    if op=="add":
        # Prefer stable identity-bearing fields.
        vals={}
        for k,v in re.findall(r'([\w-]+)=("[^"]*"|[^\s]+)',rest):
            vals[k]=v
        for key in ("name","interface","dst-address","address","chain","comment"):
            if key in vals:
                return f"add {key}={vals[key]}"
        return "add"
    return op


def _props(cmd:str):
    props={}
    for k,v in re.findall(r'([\w-]+)=("[^"]*"|[^\s]+)',cmd or ""):
        props[k]=v.strip('"')
    return props


def compare(old_content:str,new_content:str):
    old_rows=_parse(old_content)
    new_rows=_parse(new_content)
    old_map={}
    new_map={}
    for path,cmd in old_rows:
        old_map.setdefault((path,_selector(cmd)),[]).append(cmd)
    for path,cmd in new_rows:
        new_map.setdefault((path,_selector(cmd)),[]).append(cmd)

    changes=[]
    keys=set(old_map)|set(new_map)
    for key in sorted(keys):
        path,selector=key
        old=old_map.get(key,[])
        new=new_map.get(key,[])
        if old==new:
            continue
        area=_area(path)
        if old and new and len(old)==1 and len(new)==1:
            op_old=old[0].split(" ",1)[0].lower()
            op_new=new[0].split(" ",1)[0].lower()
            if op_old==op_new=="set":
                a,b=_props(old[0]),_props(new[0])
                fields=[]
                for field in sorted(set(a)|set(b)):
                    if a.get(field)!=b.get(field):
                        fields.append(f"{field}: {a.get(field,'<unset>')} → {b.get(field,'<unset>')}")
                detail="; ".join(fields) if fields else f"{old[0]} → {new[0]}"
                changes.append({"area":area,"action":"changed","detail":detail,"path":path})
                continue
        # Multiset difference for adds/removes.
        unmatched_old=list(old)
        unmatched_new=list(new)
        for cmd in list(unmatched_old):
            if cmd in unmatched_new:
                unmatched_old.remove(cmd); unmatched_new.remove(cmd)
        for cmd in unmatched_old:
            action="removed" if cmd.lower().startswith("add ") else "changed/removed"
            changes.append({"area":area,"action":action,"detail":cmd,"path":path})
        for cmd in unmatched_new:
            action="added" if cmd.lower().startswith("add ") else ("disabled" if cmd.lower().startswith("disable ") else ("enabled" if cmd.lower().startswith("enable ") else "changed/added"))
            changes.append({"area":area,"action":action,"detail":cmd,"path":path})

    # Friendly high-signal summaries for common singleton settings.
    return changes[:500]
