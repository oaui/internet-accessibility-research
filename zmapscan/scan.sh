../zmap/src/zmap -p 80 -w turk.txt -M tcp_pshack \
  --probe-args=$'text:GET / HTTP/1.1\r\nHost: youporn.com\r\n\r\n' \
  -o Turkey.txt
