FROM python:3.10

RUN apt-get update && apt-get install -y libsodium-dev tree
RUN pip install -U pip && pip install 'securesystemslib[crypto,pynacl]==0.25.0' 'tuf==v2.0.0'

ADD generate.py generate.sh /
CMD /generate.sh
