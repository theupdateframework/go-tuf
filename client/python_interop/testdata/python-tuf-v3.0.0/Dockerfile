FROM python:3.10

RUN apt-get update && apt-get install -y libsodium-dev tree
RUN pip install -U pip && pip install 'securesystemslib[crypto,pynacl]==0.28.0' 'tuf==v3.0.0'

ADD generate.py generate.sh /
CMD /generate.sh
