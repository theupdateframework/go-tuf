FROM ubuntu:trusty

RUN apt-get update
RUN apt-get install -y python python-dev python-pip libffi-dev tree
RUN pip install --no-use-wheel tuf && pip install tuf[tools]
ADD generate.py generate.sh /
CMD /generate.sh
