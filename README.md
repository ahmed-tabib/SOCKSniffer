# SOCKSniffer
## About
This tool uses the Censys search engine API to collect and test SOCKS proxy servers and package them into a text file in ip:port format.
## Requirements
This tool requires the censys python module, install using:

`pip install censys`

Using the module requires that you have a censys API key and secret, which can be obtained by creating a free account and using the following command:

`censys config`

## Usage
`python socksniffer.py [-s SOCKS_version] [-f output_file] [-m max_proxy_count] [-p port_list] [-cL country_list] [-cX country_exclusions]`
  - `-s` : SOCKS version, can be 4 or 5
  - `-f` : Path of the output file
  - `-m` : Stop once a certain number of proxies was found
  - `-p` : Look only for these ports running SOCKS proxies (comma seperated list, e.g. -p 1080,7479,5000)
  - `-cL`: Look for proxies only in these countries (comma seperated list, e.g. -cL DE,FR for proxies only in France and Germany)
  - `-cX`: Look for proxies not in these countries (comma seperated list, overwrites -cL option)
