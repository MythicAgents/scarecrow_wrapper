FROM itsafeaturemythic/mythic_base:latest

RUN apt-get update && apt-get install -y osslsigncode openssl mingw-w64 wget --no-install-recommends

WORKDIR /Mythic/

CMD ["python3", "main.py"]