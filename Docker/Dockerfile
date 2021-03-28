FROM openjdk:8-jre-alpine
EXPOSE 8080
ARG JAR_FILE=./target/demo-0.0.1-SNAPSHOT.jar
ADD ${JAR_FILE} ./demo.jar
RUN apk add --no-cache bash
RUN bash -c 'touch /demo.jar'
ENTRYPOINT ["java", "-Djava.security.edg=file:/dev/./urandom", "-jar", "demo.jar"]