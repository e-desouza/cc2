#FROM alpine:3.13
FROM redhat/ubi8-micro:latest
RUN mkdir /app
RUN mkdir /app/templates
WORKDIR /app/
COPY confisum .
COPY templates ./templates/
RUN chmod +x confisum
EXPOSE 8080
ENTRYPOINT ["./confisum"]
