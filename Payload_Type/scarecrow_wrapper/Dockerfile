FROM itsafeaturemythic/mythic_base_image:0.0.2
RUN apt-get update && apt-get install -y osslsigncode openssl mingw-w64 wget --no-install-recommends
RUN python3 -m pip install mythic-container==0.2.0rc22

WORKDIR /Mythic/

CMD ["python3", "main.py"]