FROM ubuntu:xenial

RUN apt-get update
RUN apt-get install -y python python-dev python-pip libffi-dev libssl-dev tree

RUN apt-get install -y git
RUN pip install git+https://github.com/theupdateframework/tuf.git@v0.10.2 && pip install tuf[tools]

ADD generate.py generate.sh /
CMD /generate.sh
