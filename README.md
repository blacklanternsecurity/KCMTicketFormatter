# KCMTicketFormatter
### This tools takes the output from https://github.com/fireeye/SSSDKCMExtractor and turns it into properly formatted CCACHE files for use with Windows systems.

KCMTicketFormatter integrates with https://github.com/fireeye/SSSDKCMExtractor. It takes a payload from the output of the tool and converts it to a properly-formatted CCACHE file.

![usage](https://user-images.githubusercontent.com/18042428/119726092-b5116d00-be3e-11eb-992e-73f3ab76390e.PNG)

### Requirements:

* Output from https://github.com/fireeye/SSSDKCMExtractor

* A working Python3 environment

## Usage:

To properly format your input, copy the payload from the SSSDKCMExtractor and paste it into a text file. You will provide this file to the tool with the -f flag.

~~~

usage: KCMTicketFormatter.py [-h] -f FILE [-o OUTPUT] [-v]

Format SSSD Raw Kerberos Payloads into CCACHE files for use on Windows systems.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  <Required> Specify path to the file containing SSSD Raw Kerberos Payload
  -o OUTPUT, --output OUTPUT
                        Specify name of file to output the ccache. Defaults to ticket.ccache
  -v, --verbose         Show debugging messages

~~~

Example:
~~~
python3 KCMTicketFormatter.py -f payload.txt -o user.ccache
~~~
