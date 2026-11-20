package io.github.c77cc.mongosniffer;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import org.bson.Document;

public final class Client {
    private Client() {}

    public static void main(String[] args) {
        String uri = System.getenv("MONGO_URI");
        MongoClientSettings settings = MongoClientSettings.builder()
                .applyConnectionString(new ConnectionString(uri))
                .applicationName("mongosniffer-e2e-java")
                .build();
        try (MongoClient client = MongoClients.create(settings)) {
            MongoCollection<Document> collection = client.getDatabase("e2e").getCollection("clients");
            collection.insertOne(new Document("client", "java"));
            if (collection.find(new Document("client", "java")).first() == null) {
                throw new IllegalStateException("Java driver find returned no document");
            }
        }
    }
}
