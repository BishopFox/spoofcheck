FROM python:3.7

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install -r /tmp/requirements.txt

WORKDIR /spoofcheck
COPY . .

ENTRYPOINT ["./spoofcheck.py"]
