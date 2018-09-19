# the base distribution
FROM ubuntu

# get all the dependenices
RUN apt-get update&& \
    apt-get install python3 python3-pip -y&& \
    apt-get install vim git sudo -y&& \

# add the netdog user
RUN useradd netdog -m -s /bin/bash&& \
    addgroup netdog&& \
    adduser netdog sudo&& \
    su useradd

# setup local repo
RUN git clone https://github.com/karuvally/vim_config.git&& \
    mv vim_config .vim
