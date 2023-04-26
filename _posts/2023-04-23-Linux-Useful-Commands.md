---
title: Linux useful commands
published: true
---

I'm saving these useful commands here so that you can easily access them when needed.



### [](#header-3)CUT
```
cut -d " " -f 1 notes
cut -d " " -f 1-10 notes
cut -d " " -f 1 test.txt --complement # returns fields other than the selected fields.
cut -c-1-10 test.txt # for characters
```


### [](#header-3)LN
```
ln -s test.txt test2.txt
ln test.txt test2.txt # only in the same directory
```


### [](#header-3)TR
```
cat notes | tr -s '[a-z]' '[A-Z]' 
cat notes | tr -d '[a-zA-Z: ]'
tr -d '[:blank:]'
cat notes | tr -d 'blabla'
```


### [](#header-3)LS
```
ls
ls -l # list type sorting
ls -a # show hidden files
ls -h # file size
ls --recursive #
```


### [](#header-3)FIND
```
find / -type f -group alper 2>/dev/null
find /path/to/search -type f -ctime +7 -ctime -30
find /path/to/search -type f -ctime -7
find /path/to/search -type f -ctime 0 # last 24 hours
find /path/to/search -type f -mmin -360 # last 6 hours
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null
find / -type f \( -name note1 -o -name note2 -o -name note3 \) -exec ls -la {} \; 2>>/dev/null
find . -type f -exec strings {} \; | grep -i "STMCTF"
```

### [](#header-3)STRINGS
```
strings -e l -n 10 notes
strings -f -n 10 notes
```

### [](#header-3)TCPDUMP
```
tcpdump -r network.pcap tcp
tcpdump -r network.pcap tcp -v
tcpdump -r network.pcap port <port_numarası>
tcpdump -r network.pcap src <kaynak_ip_adresi>
tcpdump -r network.pcap src <kaynak_ip_adresi> and dst <hedef_ip_adresi>
tcpdump -r network.pcap host <ip_adresi> and port <port_numarası>
tcpdump -r network.pcap -w filtered.pcap tcp
```













