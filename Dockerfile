FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package

FROM eclipse-temurin:17-jre
RUN groupadd --system app && useradd --system --gid app --no-create-home app
WORKDIR /app
COPY --from=build /app/target/vulnerablescanner-0.0.1-SNAPSHOT.jar app.jar
USER app:app
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
