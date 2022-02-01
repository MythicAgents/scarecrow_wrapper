FROM itsafeaturemythic/python38_payload:0.1.1
RUN apt-get update && apt-get install -y osslsigncode openssl mingw-w64 wget --no-install-recommends
WORKDIR /tmp

RUN wget https://go.dev/dl/go1.17.6.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.17.6.linux-amd64.tar.gz

RUN ln -s /usr/local/go/bin/go /usr/bin/go
