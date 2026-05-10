# Introduction
### Ethical Considerations
This project performs stateless network measurements against publicly routable IP space.

The scan rate is intentionally limited to reduce operational impact.
No exploitation attempts, authentication bypasses, or persistence mechanisms are used.

The measurements are intended solely for research and educational purposes.
### Sources
- [Open Observatory of Network Interference](https://ooni.org)
- [Freedom House](https://freedomhouse.org/explore-the-map?type=fiw&year=2026)
- [dev.to](https://dev.to/user32/78-million-free-ddos-amplifiers-courtesy-of-state-censorship-infrastructure-14ba)

### What is censorship?
It is widely known that not all countries allow their citizens to speak freely and actually tell their opinion in the public or in online forums like [Wikileaks](https://wikileaks.org). Some countries also do not allow any online casino services/websites like [Stake](https://stake.com).
Further, platforms like [Pornhub](https://pornhub.com), [YouPorn](https://youporn.com) and even [YouTube](https://youtube.com) or any Meta services are being censored in some countries like Russia.
Internet filtering policies differ significantly between jurisdictions and may affect access to political, social, media, gambling, or adult-content platforms.

### How to detect censorship?
There are a few different ways to check if something is being censored or not. In this documentation, a custom version of [ZMap](https://zmap.io/) will be used, to send a small payload using TCP without initiating the 3-way-handshake.

### Why does this work?
So-called `middleboxes` which are essentially censorship appliances will **eventually** modify our header containing the censored domain and respond to our data packet with either (TCP-Reset) or Status `200 OK` or `403 Forbidden` both can indicate censorship.
ZMap will then track the reply and add the middlebox to a list.
This saves resources, time and error handling as no TCP handshake is required.

### What are middleboxes?
Middleboxes are intermediary network devices positioned between a client and the destination server.

They can inspect, modify, inject, or terminate traffic in transit.

Some filtering systems inspect HTTP headers such as the Host field and inject forged TCP or HTTP responses when blocked domains are detected.

### Limitations of this approach
The measurements in this project should be interpreted as estimates rather than absolute indicators of censorship activity.
False positives may occur due to:

- transparent proxies
- caching infrastructure
- enterprise firewalls
- ISP filtering
- CDN edge behavior
- anti-abuse mitigation systems
- routing anomalies

# Methodology
## Start
To start up, I have studied the documents linked above and some more interesting papers about how the internet is being censored.
I then proceeded to write a custom version of ZMap by adding a `probe-module` `tcp_pshack` to it which then allows me to specify `--probe-args` containing the payload *`GET / HTTP/1.1\r\nHost: youporn.com\r\n\r\n`*.
Using the `scan.sh` file this can easily be customized and changed in seconds.

## Scanning
To retrieve the IP ranges of the desired countries I have written a command line tool `AApi-XV.jar` which is basically just taking ASNs as input to then resolve their IP ranges using [IPInfo API](https://asn.ipinfo.app/api/).
The ASNs can easily be copy-pasted into the input file of the Java executable from [IPIP.net](https://whois.ipip.net/iso/) which will return the corresponding ASNs based on a country input.
The website that I used to obtain the countries censorship rankings: [World Pop Review Map](https://worldpopulationreview.com/country-rankings/countries-that-censor-the-internet) 

## Most censored domains
- youporn.com
- wikileaks.org
- telegram.org
- onlyfans.com

## How to perform a scan?
1. Clone this repository
2. `cd zmapscan`
3. `nano scan.sh`: Modify the -w (Whitelist File) and -o (Output File)
4. `bash ./scan.sh`

# Results
## Ranking (based on responsiveness of the IPs)
### The percentages represent the proportion of responsive scanned IPs that returned behavior consistent with censorship-related HTTP injection or filtering responses for at least one tested domain.
### Note: The percentages should be interpreted as approximate indicators derived from observed response behavior rather than definitive measurements of nationwide censorship infrastructure
1. Russia (~16.5%)
2. Saudi Arabia (~11%)
3. China (~8%)
__IMPORTANT:__ Additional measurements are omitted for brevity.
The repository includes the tooling and methodology required to reproduce or extend the dataset

## Scan Parameters
Scan Rate: 1 packet per second
Protocol: TCP
Port: 80
Countries Tested: 16


## Conclusion
The measurements indicate that portions of the filtering infrastructure respond directly to crafted HTTP payloads, making large-scale detection possible.
Internet filtering policies vary significantly between jurisdictions and may affect access to political, social, media, gambling, or adult-content platforms
