# NetDog 

Dead simple configuration management and monitoring, for your home or office.

## Introduction

NetDog is a very simple to use configuration management and monitoring tool. You
can use it to push configurations to machines on your network and monitor their
health without spending considerable amount of time figuring out how to use it.  
As long as you know how to use a mouse and keyboard, you are good to go.

## Getting Started

NetDog is currenlty in pre-alpha stage and is under heavy development. You can
get it up and running using the following instructions.

### Prerequisites

- A non ancient Linux Kernel
- Python 3.4 or greater 
- pip
- Virtualenv

### Installing

    $ python3 -m venv netdog && cd netdog

    $ git clone https://github.com/karuvally/project_green.git src

    $ source bin/activate

    $ cd src 

    $ pip -r requirements 

### Using NetDog

- Run netdog_server.py on the server
- Create user "netdog" in client computer
- Configure visudo such that no password is asked when user "netdog" invokes sudo
- Run netdog_client.py on the client computer as user netdog
- Use webserver at server_ip:9000 to access the interface

## Contributing to NetDog

- Fork the current repo
- Fix the stuff you want to fix
- Create a pull request neatly detailing what all stuff you fixed / improved

## Built With

* [Python](http://www.python.org) - An awesome language
* [Bottle](https://bottlepy.org) - Web framework for those who like things simple
* [PyCryptodome](https://github.com/Legrandin/pycryptodome) - A sweet cryptography library

## Authors

* **Aswin Babu Karuvally** - *Initial work*

## License

This project is licensed under the MIT License - see the
[LICENSE](LICENSE) file for details

## Acknowledgments

* Hat tip to anyone whose code was used
* Inspiration
* etc

