using MongoDB.Bson;
using MongoDB.Driver;

var uri = Environment.GetEnvironmentVariable("MONGO_URI")
    ?? throw new InvalidOperationException("MONGO_URI is required");
var settings = MongoClientSettings.FromConnectionString(uri);
settings.ApplicationName = "mongosniffer-e2e-dotnet";
var client = new MongoClient(settings);
var collection = client.GetDatabase("e2e").GetCollection<BsonDocument>("clients");
await collection.InsertOneAsync(new BsonDocument("client", "dotnet"));
var result = await collection.Find(new BsonDocument("client", "dotnet")).FirstOrDefaultAsync();
if (result is null)
{
    throw new InvalidOperationException(".NET driver find returned no document");
}
